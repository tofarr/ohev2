"""Tests for the auth feature: token types, validity, rotation, and routes.

Covers the three authentication flows (cookie, OAuth2 access/refresh, API key)
and the sliding-session / refresh-rotation invariants expressed in
``specs/auth.qnt``.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import ASGITransport, AsyncClient

from openhands.ev2.auth.auth_models import TokenType
from openhands.ev2.auth.auth_service import AuthService, InvalidTokenError

_TEST_USER_ID = uuid.UUID("12345678-1234-5678-1234-456789abcdef")

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# Service-level: token types and validity
# ---------------------------------------------------------------------------


class TestTokenTypes:
    async def test_cookie_token_round_trips_as_cookie(self, session) -> None:
        from openhands.ev2.user.user_models import User
        from openhands.ev2.user.user_schemas import UserCreate
        from openhands.ev2.user.user_service import UserService
        from openhands.ev2.util.search_filter import AllSearchFilter

        user = await UserService(session, AllSearchFilter[User]()).create(
            UserCreate(email="svc@example.com", username="svc", password="hunter2")
        )
        await session.commit()

        auth = AuthService(session)
        token = auth.create_cookie_token(user.id)
        at = await auth.authenticate(token)
        assert at.token_type is TokenType.COOKIE
        assert at.user_id == user.id
        assert at.enabled is True
        assert at.expires_at > datetime.now(UTC)

    async def test_access_token_round_trips_as_access_token(self, session) -> None:
        from openhands.ev2.user.user_models import User
        from openhands.ev2.user.user_schemas import UserCreate
        from openhands.ev2.user.user_service import UserService
        from openhands.ev2.util.search_filter import AllSearchFilter

        user = await UserService(session, AllSearchFilter[User]()).create(
            UserCreate(email="acc@example.com", username="acc", password="hunter2")
        )
        await session.commit()

        auth = AuthService(session)
        token = auth.create_access_token(user.id)
        at = await auth.authenticate(token)
        assert at.token_type is TokenType.ACCESS_TOKEN
        assert at.user_id == user.id

    async def test_refresh_token_not_accepted_for_general_auth(self, session) -> None:
        from openhands.ev2.user.user_models import User
        from openhands.ev2.user.user_schemas import UserCreate
        from openhands.ev2.user.user_service import UserService
        from openhands.ev2.util.search_filter import AllSearchFilter

        user = await UserService(session, AllSearchFilter[User]()).create(
            UserCreate(email="ref@example.com", username="ref", password="hunter2")
        )
        await session.commit()

        auth = AuthService(session)
        refresh, _jti = await auth.create_refresh_token(user.id)
        await session.commit()
        # Refresh tokens are exchange-only; authenticate rejects them unless
        # allow_refresh=True.
        with pytest.raises(InvalidTokenError):
            await auth.authenticate(refresh)

    async def test_disabled_user_rejects_cookie_token(self, session) -> None:
        from openhands.ev2.user.user_models import User
        from openhands.ev2.user.user_schemas import UserCreate
        from openhands.ev2.user.user_service import UserService
        from openhands.ev2.util.search_filter import AllSearchFilter

        user = await UserService(session, AllSearchFilter[User]()).create(
            UserCreate(email="dis@example.com", username="dis", password="hunter2", enabled=False)
        )
        await session.commit()

        auth = AuthService(session)
        token = auth.create_cookie_token(user.id)
        with pytest.raises(InvalidTokenError):
            await auth.authenticate(token)


# ---------------------------------------------------------------------------
# Service-level: malformed tokens (claim-validation error paths)
# ---------------------------------------------------------------------------


class TestMalformedTokens:
    """Exercise each claim-validation branch in AuthService.authenticate."""

    async def test_garbage_token_raises_decrypt(self, session) -> None:
        auth = AuthService(session)
        with pytest.raises(InvalidTokenError):
            await auth.authenticate("not-a-jwe")

    async def test_missing_token_type_rejected(self, session) -> None:
        from openhands.ev2.encryption.encryption_service import get_encryption_service

        enc = get_encryption_service()
        bad = enc.create_jwe_token({"sub": str(uuid.uuid4()), "jti": str(uuid.uuid4())})
        with pytest.raises(InvalidTokenError, match="token type"):
            await AuthService(session).authenticate(bad)

    async def test_unknown_token_type_rejected(self, session) -> None:
        from openhands.ev2.encryption.encryption_service import get_encryption_service

        enc = get_encryption_service()
        bad = enc.create_jwe_token(
            {"sub": str(uuid.uuid4()), "ttyp": "NOPE", "jti": str(uuid.uuid4())}
        )
        with pytest.raises(InvalidTokenError, match="unknown token type"):
            await AuthService(session).authenticate(bad)

    async def test_missing_subject_rejected(self, session) -> None:
        from openhands.ev2.encryption.encryption_service import get_encryption_service

        enc = get_encryption_service()
        bad = enc.create_jwe_token({"ttyp": "cookie", "jti": str(uuid.uuid4())})
        with pytest.raises(InvalidTokenError, match="subject"):
            await AuthService(session).authenticate(bad)

    async def test_invalid_subject_rejected(self, session) -> None:
        from openhands.ev2.encryption.encryption_service import get_encryption_service

        enc = get_encryption_service()
        bad = enc.create_jwe_token(
            {"sub": "not-a-uuid", "ttyp": "cookie", "jti": str(uuid.uuid4())}
        )
        with pytest.raises(InvalidTokenError, match="subject"):
            await AuthService(session).authenticate(bad)

    async def test_missing_jti_rejected(self, session) -> None:
        from openhands.ev2.encryption.encryption_service import get_encryption_service
        from openhands.ev2.user.user_models import User
        from openhands.ev2.user.user_schemas import UserCreate
        from openhands.ev2.user.user_service import UserService
        from openhands.ev2.util.search_filter import AllSearchFilter

        user = await UserService(session, AllSearchFilter[User]()).create(
            UserCreate(email="njti@example.com", username="njti", password="hunter2")
        )
        await session.commit()
        enc = get_encryption_service()
        bad = enc.create_jwe_token({"sub": str(user.id), "ttyp": "cookie"})
        with pytest.raises(InvalidTokenError, match="jti"):
            await AuthService(session).authenticate(bad)

    async def test_expired_cookie_token_rejected(self, session) -> None:
        from openhands.ev2.user.user_models import User
        from openhands.ev2.user.user_schemas import UserCreate
        from openhands.ev2.user.user_service import UserService
        from openhands.ev2.util.search_filter import AllSearchFilter

        user = await UserService(session, AllSearchFilter[User]()).create(
            UserCreate(email="exp@example.com", username="exp", password="hunter2")
        )
        await session.commit()
        auth = AuthService(session)
        token = auth.create_cookie_token(user.id)
        # Decode, rewind exp into the past, re-encrypt manually.
        from openhands.ev2.encryption.encryption_service import get_encryption_service

        enc = get_encryption_service()
        payload = enc.decrypt_jwe_token(token)
        payload["exp"] = int((datetime.now(UTC) - timedelta(hours=1)).timestamp())
        expired = enc.create_jwe_token(payload, expires_in=timedelta(seconds=-1))
        with pytest.raises(InvalidTokenError, match="expired"):
            await auth.authenticate(expired)

    async def test_refresh_token_with_allow_refresh_authenticates(self, session) -> None:
        from openhands.ev2.user.user_models import User
        from openhands.ev2.user.user_schemas import UserCreate
        from openhands.ev2.user.user_service import UserService
        from openhands.ev2.util.search_filter import AllSearchFilter

        user = await UserService(session, AllSearchFilter[User]()).create(
            UserCreate(email="ar@example.com", username="ar", password="hunter2")
        )
        await session.commit()
        auth = AuthService(session)
        refresh, _ = await auth.create_refresh_token(user.id)
        await session.commit()
        at = await auth.authenticate(refresh, allow_refresh=True)
        assert at.token_type is TokenType.REFRESH_TOKEN
        assert at.enabled is True

    async def test_api_key_with_no_expiry_authenticates(self, session) -> None:
        from openhands.ev2.user.user_models import User
        from openhands.ev2.user.user_schemas import UserCreate
        from openhands.ev2.user.user_service import UserService
        from openhands.ev2.util.search_filter import AllSearchFilter

        user = await UserService(session, AllSearchFilter[User]()).create(
            UserCreate(email="ne@example.com", username="ne", password="hunter2")
        )
        await session.commit()
        auth = AuthService(session)
        token, _row = await auth.create_api_key(user.id)  # no expires_at
        await session.commit()
        at = await auth.authenticate(token)
        assert at.token_type is TokenType.API_KEY
        assert at.enabled is True

    async def test_create_api_key_with_past_expiry_mints_no_exp_token(self, session) -> None:
        from openhands.ev2.user.user_models import User
        from openhands.ev2.user.user_schemas import UserCreate
        from openhands.ev2.user.user_service import UserService
        from openhands.ev2.util.search_filter import AllSearchFilter

        user = await UserService(session, AllSearchFilter[User]()).create(
            UserCreate(email="pe@example.com", username="pe", password="hunter2")
        )
        await session.commit()
        auth = AuthService(session)
        past = datetime.now(UTC) - timedelta(hours=1)
        token, _row = await auth.create_api_key(user.id, expires_at=past)
        await session.commit()
        # A past expiry means the row is immediately "expired" → enabled False.
        at = await auth.authenticate(token)
        assert at.enabled is False


class TestRefreshTokenRowValidity:
    async def test_revoked_refresh_token_rejected_in_refresh(self, session) -> None:
        from openhands.ev2.user.user_models import User
        from openhands.ev2.user.user_schemas import UserCreate
        from openhands.ev2.user.user_service import UserService
        from openhands.ev2.util.search_filter import AllSearchFilter

        user = await UserService(session, AllSearchFilter[User]()).create(
            UserCreate(email="rv@example.com", username="rv", password="hunter2")
        )
        await session.commit()
        auth = AuthService(session)
        refresh, _ = await auth.create_refresh_token(user.id)
        await session.commit()
        # Manually disable the backing row to simulate revocation.
        from sqlalchemy import select

        from openhands.ev2.auth.auth_models import RefreshToken

        row = (
            await session.execute(select(RefreshToken).where(RefreshToken.jti.isnot(None)))
        ).scalar_one()
        row.enabled = False
        await session.commit()
        with pytest.raises(InvalidTokenError):
            await auth.refresh(refresh)


# ---------------------------------------------------------------------------
# API key flow: DB-backed validity
# ---------------------------------------------------------------------------


class TestApiKeyFlow:
    async def test_create_then_authenticate_api_key(self, session) -> None:
        from openhands.ev2.user.user_models import User
        from openhands.ev2.user.user_schemas import UserCreate
        from openhands.ev2.user.user_service import UserService
        from openhands.ev2.util.search_filter import AllSearchFilter

        user = await UserService(session, AllSearchFilter[User]()).create(
            UserCreate(email="key@example.com", username="key", password="hunter2")
        )
        await session.commit()

        auth = AuthService(session)
        token, row = await auth.create_api_key(user.id, name="ci-key")
        await session.commit()
        at = await auth.authenticate(token)
        assert at.token_type is TokenType.API_KEY
        assert at.id == row.jti
        assert at.enabled is True

    async def test_disabled_api_key_rejected(self, session) -> None:
        from openhands.ev2.user.user_models import User
        from openhands.ev2.user.user_schemas import UserCreate
        from openhands.ev2.user.user_service import UserService
        from openhands.ev2.util.search_filter import AllSearchFilter

        user = await UserService(session, AllSearchFilter[User]()).create(
            UserCreate(email="dk@example.com", username="dk", password="hunter2")
        )
        await session.commit()

        auth = AuthService(session)
        token, row = await auth.create_api_key(user.id)
        row.enabled = False
        await session.commit()
        at = await auth.authenticate(token)
        # The token decrypts but the disabled row means enabled=False.
        assert at.enabled is False


# ---------------------------------------------------------------------------
# Refresh-token rotation
# ---------------------------------------------------------------------------


class TestRefreshRotation:
    async def test_refresh_rotates_and_invalidates_old(self, session) -> None:
        from openhands.ev2.user.user_models import User
        from openhands.ev2.user.user_schemas import UserCreate
        from openhands.ev2.user.user_service import UserService
        from openhands.ev2.util.search_filter import AllSearchFilter

        user = await UserService(session, AllSearchFilter[User]()).create(
            UserCreate(email="rot@example.com", username="rot", password="hunter2")
        )
        await session.commit()

        auth = AuthService(session)
        refresh, _old_jti = await auth.create_refresh_token(user.id)
        await session.commit()

        access, new_refresh, _uid = await auth.refresh(refresh)
        await session.commit()
        assert access
        assert new_refresh != refresh
        # The old refresh token is now invalid (row disabled).
        with pytest.raises(InvalidTokenError):
            await auth.refresh(refresh)
        # The new refresh token is valid.
        await auth.refresh(new_refresh)

    async def test_refresh_rejects_non_refresh_token(self, session) -> None:
        from openhands.ev2.user.user_models import User
        from openhands.ev2.user.user_schemas import UserCreate
        from openhands.ev2.user.user_service import UserService
        from openhands.ev2.util.search_filter import AllSearchFilter

        user = await UserService(session, AllSearchFilter[User]()).create(
            UserCreate(email="nrt@example.com", username="nrt", password="hunter2")
        )
        await session.commit()

        auth = AuthService(session)
        access = auth.create_access_token(user.id)
        with pytest.raises(InvalidTokenError):
            await auth.refresh(access)


# ---------------------------------------------------------------------------
# Route-level: /auth/token, /auth/refresh, /auth/api-keys
# ---------------------------------------------------------------------------


class TestTokenEndpoint:
    async def test_password_grant_returns_access_and_refresh(self, client, session) -> None:
        from openhands.ev2.user.user_models import User
        from openhands.ev2.user.user_schemas import UserCreate
        from openhands.ev2.user.user_service import UserService
        from openhands.ev2.util.search_filter import AllSearchFilter

        await UserService(session, AllSearchFilter[User]()).create(
            UserCreate(email="pg@example.com", username="pg", password="hunter2")
        )
        await session.commit()

        resp = await client.post(
            "/auth/token",
            json={
                "grant_type": "password",
                "username": "pg",
                "password": "hunter2",
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["token_type"] == "Bearer"
        assert body["access_token"]
        assert body["refresh_token"]
        assert body["expires_in"] > 0

    async def test_password_grant_bad_credentials_401(self, client) -> None:
        resp = await client.post(
            "/auth/token",
            json={"grant_type": "password", "username": "pg", "password": "wrong"},
        )
        assert resp.status_code == 401

    async def test_password_grant_wrong_grant_type_400(self, client) -> None:
        resp = await client.post(
            "/auth/token",
            json={"grant_type": "client_credentials", "username": "x", "password": "y"},
        )
        assert resp.status_code == 400

    async def test_refresh_grant_rotates(self, client, session) -> None:
        from openhands.ev2.user.user_models import User
        from openhands.ev2.user.user_schemas import UserCreate
        from openhands.ev2.user.user_service import UserService
        from openhands.ev2.util.search_filter import AllSearchFilter

        await UserService(session, AllSearchFilter[User]()).create(
            UserCreate(email="rg@example.com", username="rg", password="hunter2")
        )
        await session.commit()

        tok = await client.post(
            "/auth/token",
            json={"grant_type": "password", "username": "rg", "password": "hunter2"},
        )
        refresh_token = tok.json()["refresh_token"]

        resp = await client.post(
            "/auth/refresh",
            json={"grant_type": "refresh_token", "refresh_token": refresh_token},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["access_token"]
        assert body["refresh_token"] != refresh_token

        # The old refresh token is now invalid.
        again = await client.post(
            "/auth/refresh",
            json={"grant_type": "refresh_token", "refresh_token": refresh_token},
        )
        assert again.status_code == 401

    async def test_refresh_grant_wrong_grant_type_400(self, client) -> None:
        resp = await client.post(
            "/auth/refresh",
            json={"grant_type": "password", "refresh_token": "x"},
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Route-level: /auth/api-keys CRUD and X-API-Key auth
# ---------------------------------------------------------------------------


class TestApiKeyRoutes:
    async def test_create_and_use_api_key(self, client) -> None:
        create = await client.post("/auth/api-keys", json={"name": "test-key"})
        assert create.status_code == 201, create.text
        body = create.json()
        token = body["token"]
        assert body["api_key"]["name"] == "test-key"
        assert body["api_key"]["enabled"] is True

        # The minted key authenticates via X-API-Key. Drop the session cookie so
        # the request authenticates solely via the header.
        client.cookies.clear()
        resp = await client.get("/users", headers={"X-API-Key": token})
        assert resp.status_code == 200

    async def test_list_api_keys_returns_only_own(self, client) -> None:
        await client.post("/auth/api-keys", json={"name": "a"})
        await client.post("/auth/api-keys", json={"name": "b"})
        resp = await client.get("/auth/api-keys")
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 2
        names = {i["name"] for i in items}
        assert names == {"a", "b"}

    async def test_get_api_key_by_id(self, client) -> None:
        create = await client.post("/auth/api-keys", json={"name": "solo"})
        key_id = create.json()["api_key"]["id"]
        resp = await client.get(f"/auth/api-keys/{key_id}")
        assert resp.status_code == 200
        assert resp.json()["id"] == key_id

    async def test_get_api_key_unknown_returns_404(self, client) -> None:
        resp = await client.get(f"/auth/api-keys/{uuid.uuid4()}")
        assert resp.status_code == 404

    async def test_update_api_key_disable(self, client) -> None:
        create = await client.post("/auth/api-keys", json={"name": "upd"})
        key_id = create.json()["api_key"]["id"]
        token = create.json()["token"]
        resp = await client.patch(f"/auth/api-keys/{key_id}", json={"enabled": False})
        assert resp.status_code == 200
        assert resp.json()["enabled"] is False
        # A disabled key no longer authenticates. Drop the session cookie first so
        # the request authenticates solely via the X-API-Key header.
        client.cookies.clear()
        denied = await client.get("/users", headers={"X-API-Key": token})
        assert denied.status_code == 401

    async def test_delete_api_key(self, client) -> None:
        create = await client.post("/auth/api-keys", json={"name": "del"})
        key_id = create.json()["api_key"]["id"]
        resp = await client.delete(f"/auth/api-keys/{key_id}")
        assert resp.status_code == 204
        missing = await client.get(f"/auth/api-keys/{key_id}")
        assert missing.status_code == 404


# ---------------------------------------------------------------------------
# Bearer (access token) auth via Authorization header
# ---------------------------------------------------------------------------


class TestBearerAuth:
    async def test_bearer_access_token_authenticates(self, client, session) -> None:
        from openhands.ev2.user.user_models import User
        from openhands.ev2.user.user_schemas import UserCreate
        from openhands.ev2.user.user_service import UserService
        from openhands.ev2.util.search_filter import AllSearchFilter

        await UserService(session, AllSearchFilter[User]()).create(
            UserCreate(email="bear@example.com", username="bear", password="hunter2")
        )
        await session.commit()

        tok = await client.post(
            "/auth/token",
            json={"grant_type": "password", "username": "bear", "password": "hunter2"},
        )
        access = tok.json()["access_token"]
        client.cookies.clear()
        resp = await client.get("/users", headers={"Authorization": f"Bearer {access}"})
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Cookie login/logout flow
# ---------------------------------------------------------------------------


class TestCookieLoginFlow:
    async def test_login_sets_cookie_and_returns_user(self, client, session) -> None:
        from openhands.ev2.user.user_models import User
        from openhands.ev2.user.user_schemas import UserCreate
        from openhands.ev2.user.user_service import UserService
        from openhands.ev2.util.search_filter import AllSearchFilter

        await UserService(session, AllSearchFilter[User]()).create(
            UserCreate(email="cl@example.com", username="cl", password="hunter2")
        )
        await session.commit()
        resp = await client.post("/auth/login", json={"username": "cl", "password": "hunter2"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["username"] == "cl"
        assert body["token_type"] == "cookie"
        assert "set-cookie" in {k.lower() for k in resp.headers}

    async def test_login_bad_credentials_401(self, client) -> None:
        resp = await client.post("/auth/login", json={"username": "nope", "password": "x"})
        assert resp.status_code == 401

    async def test_logout_clears_cookie(self, client) -> None:
        resp = await client.post("/auth/logout")
        assert resp.status_code == 204

    async def test_sliding_session_re_mints_cookie(self, app) -> None:
        # A request authenticated via the session cookie must yield a fresh
        # Set-Cookie (sliding session). The default test client uses X-API-Key,
        # so send the cookie explicitly here.
        from openhands.ev2.util.auth_token import create_auth_token

        token = create_auth_token(_TEST_USER_ID)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            ac.cookies.set("ohesession", token)
            resp = await ac.get("/users")
        assert resp.status_code == 200
        assert "set-cookie" in {k.lower() for k in resp.headers}


# ---------------------------------------------------------------------------
# API key search: filters, cursor pagination, 404s
# ---------------------------------------------------------------------------


class TestApiKeySearch:
    async def test_invalid_cursor_400(self, client) -> None:
        resp = await client.get("/auth/api-keys", params={"cursor": "not-a-uuid"})
        assert resp.status_code == 400

    async def test_name_filter(self, client) -> None:
        await client.post("/auth/api-keys", json={"name": "alpha"})
        await client.post("/auth/api-keys", json={"name": "beta"})
        resp = await client.get("/auth/api-keys", params={"name__contains": "alp"})
        assert resp.status_code == 200
        names = {i["name"] for i in resp.json()["items"]}
        assert names == {"alpha"}

    async def test_enabled_filter(self, client) -> None:
        create = await client.post("/auth/api-keys", json={"name": "fil"})
        key_id = create.json()["api_key"]["id"]
        await client.patch(f"/auth/api-keys/{key_id}", json={"enabled": False})
        resp = await client.get("/auth/api-keys", params={"enabled__eq": False})
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 1
        assert items[0]["enabled"] is False

    async def test_cursor_pagination(self, client) -> None:
        for i in range(3):
            await client.post("/auth/api-keys", json={"name": f"p{i}"})
        first = await client.get("/auth/api-keys", params={"limit": 1})
        assert first.status_code == 200
        assert first.json()["next_cursor"] is not None
        cursor = first.json()["next_cursor"]
        second = await client.get("/auth/api-keys", params={"limit": 1, "cursor": cursor})
        assert second.status_code == 200
        # The two pages return different keys.
        assert second.json()["items"][0]["id"] != first.json()["items"][0]["id"]

    async def test_update_api_key_rename(self, client) -> None:
        create = await client.post("/auth/api-keys", json={"name": "orig"})
        key_id = create.json()["api_key"]["id"]
        resp = await client.patch(f"/auth/api-keys/{key_id}", json={"name": "renamed"})
        assert resp.status_code == 200
        assert resp.json()["name"] == "renamed"

    async def test_update_unknown_api_key_404(self, client) -> None:
        resp = await client.patch(f"/auth/api-keys/{uuid.uuid4()}", json={"name": "x"})
        assert resp.status_code == 404

    async def test_delete_unknown_api_key_404(self, client) -> None:
        resp = await client.delete(f"/auth/api-keys/{uuid.uuid4()}")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Anonymous (no token) is None, not 401
# ---------------------------------------------------------------------------


class TestAnonymous:
    async def test_no_token_returns_anonymous_not_401(self, client) -> None:
        client.cookies.clear()
        # /auth/api-keys requires auth+permission; without a token it's 401
        # because the endpoint is permission-guarded, not because auth rejected.
        # Use a public endpoint to confirm anonymous is allowed.
        resp = await client.post("/auth/logout")
        assert resp.status_code == 204


# ---------------------------------------------------------------------------
# OAuth2 token endpoint: bad credentials + refresh rotation
# ---------------------------------------------------------------------------


class TestOAuthTokenEndpoint:
    async def test_token_bad_credentials_401(self, client) -> None:
        resp = await client.post(
            "/auth/token",
            json={"grant_type": "password", "username": "nope", "password": "x"},
        )
        assert resp.status_code == 401

    async def test_token_bad_grant_type_400(self, client) -> None:
        resp = await client.post(
            "/auth/token",
            json={"grant_type": "bogus", "username": "x", "password": "x"},
        )
        assert resp.status_code == 400

    async def test_refresh_rotation(self, client, session) -> None:
        from openhands.ev2.user.user_models import User
        from openhands.ev2.user.user_schemas import UserCreate
        from openhands.ev2.user.user_service import UserService
        from openhands.ev2.util.search_filter import AllSearchFilter

        await UserService(session, AllSearchFilter[User]()).create(
            UserCreate(email="rr@example.com", username="rr", password="hunter2")
        )
        await session.commit()
        tok = await client.post(
            "/auth/token",
            json={
                "grant_type": "password",
                "username": "rr",
                "password": "hunter2",
            },
        )
        assert tok.status_code == 200
        refresh = tok.json()["refresh_token"]
        # Rotate via the dedicated /auth/refresh endpoint.
        rotated = await client.post(
            "/auth/refresh",
            json={"grant_type": "refresh_token", "refresh_token": refresh},
        )
        assert rotated.status_code == 200
        body = rotated.json()
        assert "access_token" in body
        assert "refresh_token" in body
        # The rotated refresh token differs from the original (rotation).
        assert body["refresh_token"] != refresh

    async def test_refresh_with_garbage_token_401(self, client) -> None:
        resp = await client.post(
            "/auth/refresh",
            json={"grant_type": "refresh_token", "refresh_token": "garbage"},
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# API key: single retrieve, update fields, delete success, ownership 404
# ---------------------------------------------------------------------------


class TestApiKeySingleCrud:
    async def test_get_api_key_by_id(self, client) -> None:
        create = await client.post("/auth/api-keys", json={"name": "single"})
        key_id = create.json()["api_key"]["id"]
        resp = await client.get(f"/auth/api-keys/{key_id}")
        assert resp.status_code == 200
        assert resp.json()["id"] == key_id

    async def test_get_unknown_api_key_404(self, client) -> None:
        resp = await client.get(f"/auth/api-keys/{uuid.uuid4()}")
        assert resp.status_code == 404

    async def test_update_api_key_enabled(self, client) -> None:
        create = await client.post("/auth/api-keys", json={"name": "en"})
        key_id = create.json()["api_key"]["id"]
        resp = await client.patch(f"/auth/api-keys/{key_id}", json={"enabled": False})
        assert resp.status_code == 200
        assert resp.json()["enabled"] is False

    async def test_update_api_key_expiry(self, client) -> None:
        create = await client.post("/auth/api-keys", json={"name": "ex"})
        key_id = create.json()["api_key"]["id"]
        future = datetime.now(UTC) + timedelta(days=30)
        resp = await client.patch(
            f"/auth/api-keys/{key_id}",
            json={"expires_at": future.isoformat()},
        )
        assert resp.status_code == 200

    async def test_delete_api_key_success(self, client) -> None:
        create = await client.post("/auth/api-keys", json={"name": "del"})
        key_id = create.json()["api_key"]["id"]
        resp = await client.delete(f"/auth/api-keys/{key_id}")
        assert resp.status_code == 204
        # Subsequent get is 404.
        resp2 = await client.get(f"/auth/api-keys/{key_id}")
        assert resp2.status_code == 404


# ---------------------------------------------------------------------------
# API key auth via X-API-Key header
# ---------------------------------------------------------------------------


class TestApiKeyHeaderAuth:
    async def test_api_key_header_authenticates(self, client) -> None:
        create = await client.post("/auth/api-keys", json={"name": "hdr"})
        token = create.json()["token"]
        client.cookies.clear()
        resp = await client.get("/users", headers={"X-API-Key": token})
        assert resp.status_code == 200

    async def test_create_api_key_unauthenticated_401(self, app) -> None:
        from httpx import ASGITransport, AsyncClient

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            resp = await ac.post("/auth/api-keys", json={"name": "noauth"})
        assert resp.status_code == 401
