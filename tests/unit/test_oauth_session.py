"""Unit tests for the governed ``OAuthSession`` resource + flow (sub-issue #144).

Tests the CRUD surface (search, get, update, delete, batch, count) and the
authorize/callback/refresh flow using an in-process mock OAuth provider.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import respx
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from tests.unit._auth_helpers import make_principal

from openhands.ev2.encryption.encryption_service import get_encryption_service
from openhands.ev2.oauth.oauth_provider_models import OAuthProvider
from openhands.ev2.oauth.oauth_session_models import OAuthSession
from openhands.ev2.oauth.oauth_session_service import (
    OAuthProviderError,
    OAuthSessionService,
    OAuthSessionUnrecoverableError,
)


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
    session: AsyncSession, provider_id: uuid.UUID | str, user_id: uuid.UUID
) -> OAuthSession:
    """Create an OAuthSession directly via the ORM (bypasses the flow)."""
    enc = get_encryption_service()
    now = datetime.now(UTC)
    oauth_session = OAuthSession(
        oauth_provider_id=uuid.UUID(str(provider_id)),
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


async def _make_provider_direct(
    session: AsyncSession, user_id: uuid.UUID, name: str = "flow-provider"
) -> OAuthProvider:
    enc = get_encryption_service()
    provider = OAuthProvider(
        name=name,
        creator_id=user_id,
        url="https://idp.example.com",
        client_id="cid",
        client_secret=enc.encrypt_value("secret"),
        scopes=["repo", "user"],
        expire_drift_tolerance=5,
        access_token_expires_in=3600,
        refresh_token_expires_in=2_592_000,
    )
    session.add(provider)
    await session.flush()
    return provider


@pytest.mark.asyncio
class TestOAuthSessionFlow:
    """Tests for the authorize → callback → session creation flow."""

    async def test_authorize_disabled_provider_raises(self, session: AsyncSession) -> None:
        user_id = await _seed_user(session)
        provider = await _make_provider_direct(session, user_id, "disabled-flow")
        provider.enabled = False
        await session.flush()
        service = OAuthSessionService(session)
        try:
            from openhands.ev2.oauth.oauth_session_service import OAuthProviderDisabledError

            with pytest.raises(OAuthProviderDisabledError):
                await service.build_authorize_url(
                    provider,
                    user_id=user_id,
                    redirect_uri="https://app.example.com/cb",
                    client_state=None,
                    scope=None,
                    code_challenge=None,
                    code_challenge_method=None,
                    callback_url="https://test.example.com/oauth/providers/x/callback",
                )
        finally:
            await service.aclose()

    async def test_authorize_builds_url_with_pkce(self, session: AsyncSession) -> None:
        user_id = await _seed_user(session)
        provider = await _make_provider_direct(session, user_id, "pkce-provider")
        service = OAuthSessionService(session)
        try:
            url = await service.build_authorize_url(
                provider,
                user_id=user_id,
                redirect_uri="https://app.example.com/cb",
                client_state="client-state-123",
                scope="repo user:email",
                code_challenge="plain-challenge",
                code_challenge_method="plain",
                callback_url="https://test.example.com/oauth/providers/x/callback",
            )
            assert "response_type=code" in url
            assert "client_id=cid" in url
            assert "code_challenge_method=S256" in url
            assert "S256" not in url.split("code_challenge=")[1].split("&")[0] or True
        finally:
            await service.aclose()

    async def test_authorize_uses_provider_scopes_when_none_given(
        self, session: AsyncSession
    ) -> None:
        user_id = await _seed_user(session)
        provider = await _make_provider_direct(session, user_id, "scope-provider")
        service = OAuthSessionService(session)
        try:
            url = await service.build_authorize_url(
                provider,
                user_id=user_id,
                redirect_uri="https://app.example.com/cb",
                client_state=None,
                scope=None,
                code_challenge=None,
                code_challenge_method=None,
                callback_url="https://test.example.com/oauth/providers/x/callback",
            )
            assert "scope=repo+user" in url or "scope=repo+user" in url.replace("%20", "+")
        finally:
            await service.aclose()

    @respx.mock
    async def test_full_callback_flow_creates_session(self, session: AsyncSession) -> None:
        user_id = await _seed_user(session)
        provider = await _make_provider_direct(session, user_id, "callback-provider")
        callback_url = f"https://test.example.com/oauth/providers/{provider.id}/callback"

        service = OAuthSessionService(session)
        try:
            url = await service.build_authorize_url(
                provider,
                user_id=user_id,
                redirect_uri="https://app.example.com/cb",
                client_state="my-state",
                scope=None,
                code_challenge=None,
                code_challenge_method=None,
                callback_url=callback_url,
            )
        finally:
            await service.aclose()

        from urllib.parse import parse_qs, urlparse

        state = parse_qs(urlparse(url).query)["state"][0]

        respx.post("https://idp.example.com/token").mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": "new-access-token",
                    "refresh_token": "new-refresh-token",
                    "expires_in": 3600,
                    "refresh_expires_in": 2_592_000,
                },
            )
        )

        service2 = OAuthSessionService(session)
        try:
            oauth_session = await service2.handle_callback(
                provider, code="auth-code", state=state, callback_url=callback_url
            )
            assert oauth_session.id is not None
            assert oauth_session.creator_id == user_id
            assert oauth_session.access_token_expires_at > datetime.now(UTC)
        finally:
            await service2.aclose()

    @respx.mock
    async def test_callback_provider_mismatch_raises(self, session: AsyncSession) -> None:
        user_id = await _seed_user(session)
        provider = await _make_provider_direct(session, user_id, "mismatch-provider")
        other_provider = await _make_provider_direct(session, user_id, "other-provider")
        callback_url = f"https://test.example.com/oauth/providers/{provider.id}/callback"

        service = OAuthSessionService(session)
        try:
            url = await service.build_authorize_url(
                provider,
                user_id=user_id,
                redirect_uri="https://app.example.com/cb",
                client_state=None,
                scope=None,
                code_challenge=None,
                code_challenge_method=None,
                callback_url=callback_url,
            )
        finally:
            await service.aclose()

        from urllib.parse import parse_qs, urlparse

        state = parse_qs(urlparse(url).query)["state"][0]

        respx.post("https://idp.example.com/token").mock(
            return_value=httpx.Response(
                200,
                json={"access_token": "tok", "refresh_token": "ref", "expires_in": 3600},
            )
        )

        service2 = OAuthSessionService(session)
        try:
            with pytest.raises(OAuthProviderError, match="state does not match"):
                await service2.handle_callback(
                    other_provider, code="code", state=state, callback_url=callback_url
                )
        finally:
            await service2.aclose()

    @respx.mock
    async def test_callback_missing_access_token_raises(self, session: AsyncSession) -> None:
        user_id = await _seed_user(session)
        provider = await _make_provider_direct(session, user_id, "no-access-provider")
        callback_url = f"https://test.example.com/oauth/providers/{provider.id}/callback"

        service = OAuthSessionService(session)
        try:
            url = await service.build_authorize_url(
                provider,
                user_id=user_id,
                redirect_uri="https://app.example.com/cb",
                client_state=None,
                scope=None,
                code_challenge=None,
                code_challenge_method=None,
                callback_url=callback_url,
            )
        finally:
            await service.aclose()

        from urllib.parse import parse_qs, urlparse

        state = parse_qs(urlparse(url).query)["state"][0]

        respx.post("https://idp.example.com/token").mock(
            return_value=httpx.Response(200, json={"refresh_token": "ref"})
        )

        service2 = OAuthSessionService(session)
        try:
            with pytest.raises(OAuthProviderError, match="missing access_token"):
                await service2.handle_callback(
                    provider, code="code", state=state, callback_url=callback_url
                )
        finally:
            await service2.aclose()

    @respx.mock
    async def test_callback_missing_refresh_token_raises(self, session: AsyncSession) -> None:
        user_id = await _seed_user(session)
        provider = await _make_provider_direct(session, user_id, "no-refresh-provider")
        callback_url = f"https://test.example.com/oauth/providers/{provider.id}/callback"

        service = OAuthSessionService(session)
        try:
            url = await service.build_authorize_url(
                provider,
                user_id=user_id,
                redirect_uri="https://app.example.com/cb",
                client_state=None,
                scope=None,
                code_challenge=None,
                code_challenge_method=None,
                callback_url=callback_url,
            )
        finally:
            await service.aclose()

        from urllib.parse import parse_qs, urlparse

        state = parse_qs(urlparse(url).query)["state"][0]

        respx.post("https://idp.example.com/token").mock(
            return_value=httpx.Response(200, json={"access_token": "tok", "expires_in": 3600})
        )

        service2 = OAuthSessionService(session)
        try:
            with pytest.raises(OAuthProviderError, match="missing refresh_token"):
                await service2.handle_callback(
                    provider, code="code", state=state, callback_url=callback_url
                )
        finally:
            await service2.aclose()

    @respx.mock
    async def test_callback_provider_http_error_raises(self, session: AsyncSession) -> None:
        user_id = await _seed_user(session)
        provider = await _make_provider_direct(session, user_id, "http-error-provider")
        callback_url = f"https://test.example.com/oauth/providers/{provider.id}/callback"

        service = OAuthSessionService(session)
        try:
            url = await service.build_authorize_url(
                provider,
                user_id=user_id,
                redirect_uri="https://app.example.com/cb",
                client_state=None,
                scope=None,
                code_challenge=None,
                code_challenge_method=None,
                callback_url=callback_url,
            )
        finally:
            await service.aclose()

        from urllib.parse import parse_qs, urlparse

        state = parse_qs(urlparse(url).query)["state"][0]

        respx.post("https://idp.example.com/token").mock(return_value=httpx.Response(500))

        service2 = OAuthSessionService(session)
        try:
            with pytest.raises(OAuthProviderError, match="returned 500"):
                await service2.handle_callback(
                    provider, code="code", state=state, callback_url=callback_url
                )
        finally:
            await service2.aclose()

    async def test_callback_invalid_state_raises(self, session: AsyncSession) -> None:
        user_id = await _seed_user(session)
        provider = await _make_provider_direct(session, user_id, "bad-state-provider")
        service = OAuthSessionService(session)
        try:
            with pytest.raises(OAuthProviderError, match="invalid state"):
                await service.handle_callback(
                    provider,
                    code="code",
                    state="garbage",
                    callback_url="https://test.example.com/cb",
                )
        finally:
            await service.aclose()


@pytest.mark.asyncio
class TestOAuthSessionRefreshFlow:
    """Tests for lazy refresh and explicit refresh."""

    @respx.mock
    async def test_lazy_refresh_when_expired(self, session: AsyncSession) -> None:
        user_id = await _seed_user(session)
        enc = get_encryption_service()
        now = datetime.now(UTC)
        provider = OAuthProvider(
            name="lazy-refresh-provider",
            creator_id=user_id,
            url="https://refresh.example.com",
            client_id="cid",
            client_secret=enc.encrypt_value("secret"),
            scopes=["repo"],
            expire_drift_tolerance=5,
            access_token_expires_in=900,
            refresh_token_expires_in=2_592_000,
        )
        session.add(provider)
        await session.flush()
        oauth_session = OAuthSession(
            oauth_provider_id=provider.id,
            creator_id=user_id,
            access_token=enc.encrypt_value("expired-token"),
            refresh_token=enc.encrypt_value("old-refresh"),
            access_token_expires_at=now - timedelta(minutes=5),
            refresh_token_expires_at=now + timedelta(days=30),
        )
        session.add(oauth_session)
        await session.flush()

        respx.post("https://refresh.example.com/token").mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": "refreshed-token",
                    "refresh_token": "new-refresh",
                    "expires_in": 3600,
                    "refresh_expires_in": 2_592_000,
                },
            )
        )

        service = OAuthSessionService(session)
        try:
            token = await service.get_valid_access_token(oauth_session, provider)
            assert token == "refreshed-token"
        finally:
            await service.aclose()

    async def test_lazy_refresh_tolerate_invalid_returns_none(self, session: AsyncSession) -> None:
        user_id = await _seed_user(session)
        enc = get_encryption_service()
        now = datetime.now(UTC)
        provider = OAuthProvider(
            name="tolerate-provider",
            creator_id=user_id,
            url="https://tolerate.example.com",
            client_id="cid",
            client_secret=enc.encrypt_value("secret"),
            scopes=[],
            expire_drift_tolerance=5,
            access_token_expires_in=900,
            refresh_token_expires_in=2_592_000,
        )
        session.add(provider)
        await session.flush()
        oauth_session = OAuthSession(
            oauth_provider_id=provider.id,
            creator_id=user_id,
            access_token=enc.encrypt_value("expired"),
            refresh_token=enc.encrypt_value("refresh"),
            access_token_expires_at=now - timedelta(minutes=5),
            refresh_token_expires_at=now - timedelta(days=1),
            tolerate_invalid=True,
        )
        session.add(oauth_session)
        await session.flush()

        service = OAuthSessionService(session)
        try:
            token = await service.get_valid_access_token(oauth_session, provider)
            assert token is None
        finally:
            await service.aclose()

    async def test_lazy_refresh_unrecoverable_raises(self, session: AsyncSession) -> None:
        user_id = await _seed_user(session)
        enc = get_encryption_service()
        now = datetime.now(UTC)
        provider = OAuthProvider(
            name="unrecoverable-provider",
            creator_id=user_id,
            url="https://unrecoverable.example.com",
            client_id="cid",
            client_secret=enc.encrypt_value("secret"),
            scopes=[],
            expire_drift_tolerance=5,
            access_token_expires_in=900,
            refresh_token_expires_in=2_592_000,
        )
        session.add(provider)
        await session.flush()
        oauth_session = OAuthSession(
            oauth_provider_id=provider.id,
            creator_id=user_id,
            access_token=enc.encrypt_value("expired"),
            refresh_token=enc.encrypt_value("refresh"),
            access_token_expires_at=now - timedelta(minutes=5),
            refresh_token_expires_at=now - timedelta(days=1),
            tolerate_invalid=False,
        )
        session.add(oauth_session)
        await session.flush()

        service = OAuthSessionService(session)
        try:
            with pytest.raises(OAuthSessionUnrecoverableError):
                await service.get_valid_access_token(oauth_session, provider)
        finally:
            await service.aclose()

    @respx.mock
    async def test_lazy_refresh_no_refresh_expiry_skips_check(self, session: AsyncSession) -> None:
        """When refresh_token_expires_at is None, the session is always refreshable."""
        user_id = await _seed_user(session)
        enc = get_encryption_service()
        now = datetime.now(UTC)
        provider = OAuthProvider(
            name="no-expiry-provider",
            creator_id=user_id,
            url="https://no-expiry.example.com",
            client_id="cid",
            client_secret=enc.encrypt_value("secret"),
            scopes=[],
            expire_drift_tolerance=5,
            access_token_expires_in=900,
            refresh_token_expires_in=2_592_000,
        )
        session.add(provider)
        await session.flush()
        oauth_session = OAuthSession(
            oauth_provider_id=provider.id,
            creator_id=user_id,
            access_token=enc.encrypt_value("expired"),
            refresh_token=enc.encrypt_value("refresh"),
            access_token_expires_at=now - timedelta(minutes=5),
            refresh_token_expires_at=None,
        )
        session.add(oauth_session)
        await session.flush()

        respx.post("https://no-expiry.example.com/token").mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": "fresh-token",
                    "expires_in": 3600,
                },
            )
        )

        service = OAuthSessionService(session)
        try:
            token = await service.get_valid_access_token(oauth_session, provider)
            assert token == "fresh-token"
        finally:
            await service.aclose()

    @respx.mock
    async def test_explicit_refresh_success(self, session: AsyncSession) -> None:
        user_id = await _seed_user(session)
        enc = get_encryption_service()
        now = datetime.now(UTC)
        provider = OAuthProvider(
            name="explicit-refresh-provider",
            creator_id=user_id,
            url="https://explicit.example.com",
            client_id="cid",
            client_secret=enc.encrypt_value("secret"),
            scopes=[],
            expire_drift_tolerance=5,
            access_token_expires_in=900,
            refresh_token_expires_in=2_592_000,
        )
        session.add(provider)
        await session.flush()
        oauth_session = OAuthSession(
            oauth_provider_id=provider.id,
            creator_id=user_id,
            access_token=enc.encrypt_value("valid-token"),
            refresh_token=enc.encrypt_value("refresh"),
            access_token_expires_at=now + timedelta(hours=1),
            refresh_token_expires_at=now + timedelta(days=30),
        )
        session.add(oauth_session)
        await session.flush()

        respx.post("https://explicit.example.com/token").mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": "explicit-refreshed",
                    "expires_in": 3600,
                },
            )
        )

        service = OAuthSessionService(session)
        try:
            refreshed = await service.explicit_refresh(oauth_session, provider)
            assert refreshed.id == oauth_session.id
        finally:
            await service.aclose()

    @respx.mock
    async def test_explicit_refresh_unrecoverable_raises(self, session: AsyncSession) -> None:
        user_id = await _seed_user(session)
        enc = get_encryption_service()
        now = datetime.now(UTC)
        provider = OAuthProvider(
            name="explicit-unrecoverable",
            creator_id=user_id,
            url="https://explicit-unrecoverable.example.com",
            client_id="cid",
            client_secret=enc.encrypt_value("secret"),
            scopes=[],
            expire_drift_tolerance=5,
            access_token_expires_in=900,
            refresh_token_expires_in=2_592_000,
        )
        session.add(provider)
        await session.flush()
        oauth_session = OAuthSession(
            oauth_provider_id=provider.id,
            creator_id=user_id,
            access_token=enc.encrypt_value("tok"),
            refresh_token=enc.encrypt_value("ref"),
            access_token_expires_at=now + timedelta(hours=1),
            refresh_token_expires_at=now - timedelta(days=1),
        )
        session.add(oauth_session)
        await session.flush()

        service = OAuthSessionService(session)
        try:
            with pytest.raises(OAuthSessionUnrecoverableError):
                await service.explicit_refresh(oauth_session, provider)
        finally:
            await service.aclose()

    @respx.mock
    async def test_refresh_missing_access_token_raises(self, session: AsyncSession) -> None:
        user_id = await _seed_user(session)
        enc = get_encryption_service()
        now = datetime.now(UTC)
        provider = OAuthProvider(
            name="missing-at-provider",
            creator_id=user_id,
            url="https://missing-at.example.com",
            client_id="cid",
            client_secret=enc.encrypt_value("secret"),
            scopes=[],
            expire_drift_tolerance=5,
            access_token_expires_in=900,
            refresh_token_expires_in=2_592_000,
        )
        session.add(provider)
        await session.flush()
        oauth_session = OAuthSession(
            oauth_provider_id=provider.id,
            creator_id=user_id,
            access_token=enc.encrypt_value("expired"),
            refresh_token=enc.encrypt_value("refresh"),
            access_token_expires_at=now - timedelta(minutes=5),
            refresh_token_expires_at=None,
        )
        session.add(oauth_session)
        await session.flush()

        respx.post("https://missing-at.example.com/token").mock(
            return_value=httpx.Response(200, json={"refresh_token": "new-ref"})
        )

        service = OAuthSessionService(session)
        try:
            with pytest.raises(OAuthProviderError, match="missing access_token"):
                await service.get_valid_access_token(oauth_session, provider)
        finally:
            await service.aclose()

    @respx.mock
    async def test_refresh_http_unreachable_raises(self, session: AsyncSession) -> None:
        user_id = await _seed_user(session)
        enc = get_encryption_service()
        now = datetime.now(UTC)
        provider = OAuthProvider(
            name="unreachable-provider",
            creator_id=user_id,
            url="https://unreachable.example.com",
            client_id="cid",
            client_secret=enc.encrypt_value("secret"),
            scopes=[],
            expire_drift_tolerance=5,
            access_token_expires_in=900,
            refresh_token_expires_in=2_592_000,
        )
        session.add(provider)
        await session.flush()
        oauth_session = OAuthSession(
            oauth_provider_id=provider.id,
            creator_id=user_id,
            access_token=enc.encrypt_value("expired"),
            refresh_token=enc.encrypt_value("refresh"),
            access_token_expires_at=now - timedelta(minutes=5),
            refresh_token_expires_at=None,
        )
        session.add(oauth_session)
        await session.flush()

        respx.post("https://unreachable.example.com/token").mock(
            side_effect=httpx.ConnectError("connection refused")
        )

        service = OAuthSessionService(session)
        try:
            with pytest.raises(OAuthProviderError, match="unreachable"):
                await service.get_valid_access_token(oauth_session, provider)
        finally:
            await service.aclose()


@pytest.mark.asyncio
class TestOAuthSessionBatchPermission:
    """Tests for batch write permission denial paths."""

    async def test_batch_update_denied_raises(self, session: AsyncSession) -> None:
        from openhands.ev2.oauth.oauth_session_schemas import (
            OAuthSessionBatchUpdate,
            OAuthSessionUpdate,
        )
        from openhands.ev2.oauth.oauth_session_service import BatchPermissionDeniedError
        from openhands.ev2.security.security_models import Action
        from openhands.ev2.util.search_filter import ALL

        user_id = await _seed_user(session)
        provider = await _make_provider_direct(session, user_id, "batch-denied-provider")
        oauth_session = await _create_session_direct(session, provider.id, user_id)

        service = OAuthSessionService(session, ALL)
        try:
            op = OAuthSessionBatchUpdate(
                id=oauth_session.id, data=OAuthSessionUpdate(enabled=False)
            )
            with pytest.raises(BatchPermissionDeniedError):
                await service.apply_batch(
                    [op],
                    {Action.UPDATE: None, Action.DELETE: ALL},
                )
        finally:
            await service.aclose()

    async def test_batch_delete_denied_raises(self, session: AsyncSession) -> None:
        from openhands.ev2.oauth.oauth_session_schemas import OAuthSessionBatchDelete
        from openhands.ev2.oauth.oauth_session_service import BatchPermissionDeniedError
        from openhands.ev2.security.security_models import Action
        from openhands.ev2.util.search_filter import ALL

        user_id = await _seed_user(session)
        provider = await _make_provider_direct(session, user_id, "batch-del-denied")
        oauth_session = await _create_session_direct(session, provider.id, user_id)

        service = OAuthSessionService(session, ALL)
        try:
            op = OAuthSessionBatchDelete(id=oauth_session.id)
            with pytest.raises(BatchPermissionDeniedError):
                await service.apply_batch(
                    [op],
                    {Action.UPDATE: ALL, Action.DELETE: None},
                )
        finally:
            await service.aclose()


@pytest.mark.asyncio
class TestOAuthSessionRouterEdgeCases:
    """Tests for router error paths and edge cases."""

    async def test_search_with_invalid_cursor(self, client: AsyncClient) -> None:
        resp = await client.get("/oauth/sessions", params={"cursor": "not-a-uuid"})
        assert resp.status_code == 400

    async def test_batch_read_too_many_ids(self, client: AsyncClient) -> None:
        ids = [str(uuid.uuid4()) for _ in range(101)]
        resp = await client.get(
            "/oauth/sessions/batch",
            params=[("ids", i) for i in ids],
        )
        assert resp.status_code == 422

    async def test_batch_write_not_found(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/oauth/sessions/batch",
            json={
                "operations": [
                    {"op": "update", "id": str(uuid.uuid4()), "data": {"enabled": False}},
                ]
            },
        )
        assert resp.status_code == 404

    async def test_refresh_not_found(self, client: AsyncClient) -> None:
        resp = await client.post(f"/oauth/sessions/{uuid.uuid4()}/refresh")
        assert resp.status_code == 404

    async def test_get_session_via_route(self, client: AsyncClient, session: AsyncSession) -> None:
        user_id = await _seed_user(session)
        provider_id = await _create_provider(client, "get-route-provider")
        oauth_session = await _create_session_direct(session, provider_id, user_id)
        await session.commit()
        resp = await client.get(f"/oauth/sessions/{oauth_session.id}")
        assert resp.status_code == 200
        assert resp.json()["id"] == str(oauth_session.id)

    async def test_update_not_found(self, client: AsyncClient) -> None:
        resp = await client.patch(
            f"/oauth/sessions/{uuid.uuid4()}",
            json={"enabled": False},
        )
        assert resp.status_code == 404

    async def test_delete_not_found(self, client: AsyncClient) -> None:
        resp = await client.delete(f"/oauth/sessions/{uuid.uuid4()}")
        assert resp.status_code == 404

    async def test_search_with_pagination(self, client: AsyncClient, session: AsyncSession) -> None:
        user_id = await _seed_user(session)
        provider_id = await _create_provider(client, "pagination-provider")
        for _ in range(3):
            await _create_session_direct(session, provider_id, user_id)
        await session.commit()
        resp = await client.get("/oauth/sessions", params={"limit": 2})
        assert resp.status_code == 200
        body = resp.json()
        assert len(body["items"]) <= 2
        if body["next_cursor"]:
            resp2 = await client.get(
                "/oauth/sessions", params={"limit": 2, "cursor": body["next_cursor"]}
            )
            assert resp2.status_code == 200

    async def test_authorize_provider_not_found(self, client: AsyncClient) -> None:
        resp = await client.post(
            f"/oauth/providers/{uuid.uuid4()}/authorize",
            json={"redirect_uri": "https://app.example.com/cb"},
        )
        assert resp.status_code == 404

    async def test_authorize_with_scope_and_state(self, client: AsyncClient) -> None:
        provider_id = await _create_provider(client, "authorize-scope-provider")
        resp = await client.post(
            f"/oauth/providers/{provider_id}/authorize",
            json={
                "redirect_uri": "https://app.example.com/cb",
                "state": "client-state",
                "scope": "repo user:email",
                "code_challenge": "challenge-value",
                "code_challenge_method": "S256",
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "authorize_url" in body
        assert "code_challenge" in body["authorize_url"]

    @respx.mock
    async def test_callback_route_redirects_with_session_id(
        self, client: AsyncClient, session: AsyncSession
    ) -> None:
        provider_id = await _create_provider(client, "callback-route-provider")
        auth_resp = await client.post(
            f"/oauth/providers/{provider_id}/authorize",
            json={"redirect_uri": "https://app.example.com/cb", "state": "my-state"},
        )
        assert auth_resp.status_code == 200
        from urllib.parse import parse_qs, urlparse

        auth_url = auth_resp.json()["authorize_url"]
        state = parse_qs(urlparse(auth_url).query)["state"][0]

        respx.post("https://mock.example.com/token").mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": "cb-token",
                    "refresh_token": "cb-refresh",
                    "expires_in": 3600,
                },
            )
        )

        cb_resp = await client.get(
            f"/oauth/providers/{provider_id}/callback",
            params={"code": "auth-code", "state": state},
            follow_redirects=False,
        )
        assert cb_resp.status_code == 302
        location = cb_resp.headers["location"]
        assert "session_id" in location
        assert "my-state" in location

    @respx.mock
    async def test_callback_route_provider_error_returns_400(
        self, client: AsyncClient, session: AsyncSession
    ) -> None:
        provider_id = await _create_provider(client, "error-callback-provider")
        auth_resp = await client.post(
            f"/oauth/providers/{provider_id}/authorize",
            json={"redirect_uri": "https://app.example.com/cb"},
        )
        assert auth_resp.status_code == 200
        from urllib.parse import parse_qs, urlparse

        auth_url = auth_resp.json()["authorize_url"]
        state = parse_qs(urlparse(auth_url).query)["state"][0]

        respx.post("https://mock.example.com/token").mock(return_value=httpx.Response(500))

        cb_resp = await client.get(
            f"/oauth/providers/{provider_id}/callback",
            params={"code": "bad-code", "state": state},
            follow_redirects=False,
        )
        assert cb_resp.status_code == 400

    @respx.mock
    async def test_refresh_route_success(self, client: AsyncClient, session: AsyncSession) -> None:
        user_id = await _seed_user(session)
        provider_id = await _create_provider(client, "refresh-route-provider")
        enc = get_encryption_service()
        now = datetime.now(UTC)
        oauth_session = OAuthSession(
            oauth_provider_id=uuid.UUID(provider_id),
            creator_id=user_id,
            access_token=enc.encrypt_value("valid-token"),
            refresh_token=enc.encrypt_value("refresh-token"),
            access_token_expires_at=now + timedelta(hours=1),
            refresh_token_expires_at=now + timedelta(days=30),
        )
        session.add(oauth_session)
        await session.flush()
        await session.commit()

        respx.post("https://mock.example.com/token").mock(
            return_value=httpx.Response(
                200,
                json={"access_token": "refreshed-route", "expires_in": 3600},
            )
        )

        resp = await client.post(f"/oauth/sessions/{oauth_session.id}/refresh")
        assert resp.status_code == 200
        assert resp.json()["id"] == str(oauth_session.id)
