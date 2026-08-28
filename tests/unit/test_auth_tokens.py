"""Tests for :class:`TokenService` in :mod:`openhands.ev2.auth.auth_tokens`.

Covers JWE token issuance, authentication (per token type), API-key backing
rows, and refresh-token rotation (sliding window). Uses a real DB session and
the encryption service so the JWE round-trip is exercised end-to-end.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text

from openhands.ev2.auth.auth_models import ApiKey, RefreshToken, TokenType
from openhands.ev2.auth.auth_tokens import InvalidTokenError, TokenService
from openhands.ev2.config import get_config
from openhands.ev2.util.auth_token import create_auth_token

_TEST_USER_ID = uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
_OTHER_USER_ID = uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")


async def _seed_user(session, user_id: uuid.UUID = _TEST_USER_ID, enabled: bool = True) -> None:
    await session.execute(
        text(
            "INSERT INTO users (id, email, username, enabled) "
            "VALUES (:id, :email, :username, :enabled) "
            "ON CONFLICT (id) DO NOTHING"
        ),
        {
            "id": user_id,
            "email": f"{user_id}@example.com",
            "username": f"u-{user_id.hex[:8]}",
            "enabled": enabled,
        },
    )
    await session.flush()


def _seeded_service(session) -> TokenService:
    return TokenService(session)


# --------------------------------------------------------------------------- #
# Cookie / access tokens
# --------------------------------------------------------------------------- #


class TestCookieAndAccessToken:
    async def test_create_cookie_token_round_trips(self, session) -> None:
        await _seed_user(session)
        svc = _seeded_service(session)
        token = svc.create_cookie_token(_TEST_USER_ID)
        auth = await svc.authenticate(token)
        assert auth.user_id == _TEST_USER_ID
        assert auth.token_type is TokenType.COOKIE
        assert auth.enabled is True

    async def test_create_access_token_round_trips(self, session) -> None:
        await _seed_user(session)
        svc = _seeded_service(session)
        token = svc.create_access_token(_TEST_USER_ID)
        auth = await svc.authenticate(token)
        assert auth.token_type is TokenType.ACCESS_TOKEN
        assert auth.user_id == _TEST_USER_ID

    async def test_reissue_cookie_mints_fresh_cookie(self, session) -> None:
        await _seed_user(session)
        svc = _seeded_service(session)
        first = svc.create_cookie_token(_TEST_USER_ID)
        second = svc.reissue_cookie(_TEST_USER_ID)
        assert first != second
        auth = await svc.authenticate(second)
        assert auth.user_id == _TEST_USER_ID

    async def test_extract_user_id_via_util_mints_compatible_cookie(self, session) -> None:
        """The util.create_auth_token mints a COOKIE the service authenticates."""
        await _seed_user(session)
        token = create_auth_token(_TEST_USER_ID)
        auth = await _seeded_service(session).authenticate(token)
        assert auth.user_id == _TEST_USER_ID
        assert auth.token_type is TokenType.COOKIE


# --------------------------------------------------------------------------- #
# Authentication failures
# --------------------------------------------------------------------------- #


class TestAuthenticateFailures:
    async def test_garbage_token_raises(self, session) -> None:
        await _seed_user(session)
        with pytest.raises(InvalidTokenError):
            await _seeded_service(session).authenticate("not-a-jwe")

    async def test_disabled_user_rejected(self, session) -> None:
        await _seed_user(session, enabled=False)
        token = create_auth_token(_TEST_USER_ID)
        with pytest.raises(InvalidTokenError):
            await _seeded_service(session).authenticate(token)

    async def test_unknown_user_rejected(self, session) -> None:
        token = create_auth_token(_OTHER_USER_ID)
        with pytest.raises(InvalidTokenError):
            await _seeded_service(session).authenticate(token)

    async def test_refresh_token_not_accepted_as_bearer(self, session) -> None:
        await _seed_user(session)
        svc = _seeded_service(session)
        refresh, _jti = await svc.create_refresh_token(_TEST_USER_ID)
        with pytest.raises(InvalidTokenError):
            await svc.authenticate(refresh)

    async def test_refresh_token_accepted_with_allow_refresh(self, session) -> None:
        await _seed_user(session)
        svc = _seeded_service(session)
        refresh, _jti = await svc.create_refresh_token(_TEST_USER_ID)
        auth = await svc.authenticate(refresh, allow_refresh=True)
        assert auth.token_type is TokenType.REFRESH_TOKEN
        assert auth.enabled is True


# --------------------------------------------------------------------------- #
# API keys
# --------------------------------------------------------------------------- #


class TestApiKeys:
    async def test_create_and_authenticate_api_key(self, session) -> None:
        await _seed_user(session)
        svc = _seeded_service(session)
        token, row = await svc.create_api_key(_TEST_USER_ID, name="ci-key")
        assert isinstance(row, ApiKey)
        assert row.name == "ci-key"
        auth = await svc.authenticate(token)
        assert auth.token_type is TokenType.API_KEY
        assert auth.user_id == _TEST_USER_ID
        assert auth.enabled is True

    async def test_api_key_with_expiry_authenticates_until_expiry(self, session) -> None:
        await _seed_user(session)
        svc = _seeded_service(session)
        expires = datetime.now(UTC) + timedelta(hours=1)
        token, _row = await svc.create_api_key(_TEST_USER_ID, expires_at=expires)
        auth = await svc.authenticate(token)
        assert auth.enabled is True

    async def test_disabled_api_key_row_rejected(self, session) -> None:
        await _seed_user(session)
        svc = _seeded_service(session)
        token, row = await svc.create_api_key(_TEST_USER_ID)
        row.enabled = False
        await session.flush()
        auth = await svc.authenticate(token)
        assert auth.enabled is False

    async def test_deleted_api_key_row_rejected(self, session) -> None:
        await _seed_user(session)
        svc = _seeded_service(session)
        token, row = await svc.create_api_key(_TEST_USER_ID)
        await session.delete(row)
        await session.flush()
        auth = await svc.authenticate(token)
        assert auth.enabled is False


# --------------------------------------------------------------------------- #
# Refresh-token rotation
# --------------------------------------------------------------------------- #


class TestRefreshRotation:
    async def test_refresh_rotates_pair(self, session) -> None:
        await _seed_user(session)
        svc = _seeded_service(session)
        refresh, _original_jti = await svc.create_refresh_token(_TEST_USER_ID)
        access, new_refresh, user_id = await svc.refresh(refresh)
        assert user_id == _TEST_USER_ID
        assert access
        assert new_refresh
        assert new_refresh != refresh
        # New refresh token authenticates (allow_refresh); old one is revoked
        # (its backing row is disabled, so authenticate reports enabled=False).
        new_auth = await svc.authenticate(new_refresh, allow_refresh=True)
        assert new_auth.enabled is True
        old_auth = await svc.authenticate(refresh, allow_refresh=True)
        assert old_auth.enabled is False

    async def test_refresh_revoked_old_token_rejected(self, session) -> None:
        await _seed_user(session)
        svc = _seeded_service(session)
        refresh, _jti = await svc.create_refresh_token(_TEST_USER_ID)
        await svc.refresh(refresh)
        with pytest.raises(InvalidTokenError):
            await svc.refresh(refresh)

    async def test_refresh_wrong_type_rejected(self, session) -> None:
        await _seed_user(session)
        svc = _seeded_service(session)
        cookie = svc.create_cookie_token(_TEST_USER_ID)
        with pytest.raises(InvalidTokenError):
            await svc.refresh(cookie)

    async def test_refresh_sliding_capped_by_absolute_ttl(self, session) -> None:
        """Successor expiry <= original created_at + absolute refresh TTL."""
        await _seed_user(session)
        svc = _seeded_service(session)
        refresh, _jti = await svc.create_refresh_token(_TEST_USER_ID)
        _, new_refresh, _ = await svc.refresh(refresh)
        new_auth = await svc.authenticate(new_refresh, allow_refresh=True)
        cfg = get_config()
        cap = datetime.now(UTC) + timedelta(seconds=cfg.auth_refresh_token_ttl_seconds)
        assert new_auth.expires_at <= cap


# --------------------------------------------------------------------------- #
# Backing-row helpers (direct)
# --------------------------------------------------------------------------- #


class TestBackingRows:
    async def test_refresh_token_live_checks_row(self, session) -> None:
        await _seed_user(session)
        svc = _seeded_service(session)
        _, jti = await svc.create_refresh_token(_TEST_USER_ID)
        assert await svc._refresh_token_live(jti) is True

    async def test_refresh_token_live_false_for_disabled(self, session) -> None:
        await _seed_user(session)
        svc = _seeded_service(session)
        _, jti = await svc.create_refresh_token(_TEST_USER_ID)
        row = await svc._load_refresh_row(jti)
        assert row is not None
        row.enabled = False
        await session.flush()
        assert await svc._refresh_token_live(jti) is False

    async def test_api_key_live_checks_row(self, session) -> None:
        await _seed_user(session)
        svc = _seeded_service(session)
        _, row = await svc.create_api_key(_TEST_USER_ID)
        assert await svc._api_key_live(row.jti) is True

    async def test_api_key_live_false_for_missing(self, session) -> None:
        await _seed_user(session)
        svc = _seeded_service(session)
        assert await svc._api_key_live(uuid.uuid4()) is False

    async def test_refresh_row_persisted(self, session) -> None:
        await _seed_user(session)
        svc = _seeded_service(session)
        _, jti = await svc.create_refresh_token(_TEST_USER_ID)
        row = await svc._load_refresh_row(jti)
        assert isinstance(row, RefreshToken)
        assert row.jti == jti
