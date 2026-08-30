"""Tests for :class:`TokenService` in :mod:`openhands.ev2.auth.auth_tokens`.

Covers JWE token issuance (synced to IdP-backed rows), authentication (per
token type), and API-key backing rows. Token rotation is federated and
covered by ``test_auth_service.py`` (``exchange_refresh_token``); these tests
exercise minting + validation only. Uses a real DB session and the encryption
service so the JWE round-trip is exercised end-to-end.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text

from openhands.ev2.auth.auth_models import (
    ApiKey,
    IdpAccessToken,
    IdpRefreshToken,
    TokenType,
)
from openhands.ev2.auth.auth_tokens import InvalidTokenError, TokenService
from openhands.ev2.encryption.encryption_service import get_encryption_service
from openhands.ev2.util.auth_token import create_auth_token

_TEST_USER_ID = uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
_OTHER_USER_ID = uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
# A future expiry mirroring what the IdP would advertise (drift-adjusted).
_ACCESS_EXPIRES_AT = datetime.now(UTC) + timedelta(hours=1)
_REFRESH_EXPIRES_AT = datetime.now(UTC) + timedelta(days=30)


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


async def _seed_idp_rows(
    session,
    *,
    user_id: uuid.UUID = _TEST_USER_ID,
    access_expires_at: datetime = _ACCESS_EXPIRES_AT,
    refresh_expires_at: datetime = _REFRESH_EXPIRES_AT,
) -> tuple[IdpRefreshToken, IdpAccessToken]:
    """Persist an IdP refresh + access row pair (the federated grant backing tokens)."""
    enc = get_encryption_service()
    refresh_row = IdpRefreshToken(
        user_id=user_id,
        refresh_token=enc.encrypt_value("idp-refresh"),
        expires_at=refresh_expires_at,
    )
    session.add(refresh_row)
    await session.flush()
    access_row = IdpAccessToken(
        refresh_token_id=refresh_row.id,
        access_token=enc.encrypt_value("idp-access"),
        expires_at=access_expires_at,
    )
    session.add(access_row)
    await session.flush()
    return refresh_row, access_row


def _seeded_service(session) -> TokenService:
    return TokenService(session)


# --------------------------------------------------------------------------- #
# Cookie / access tokens (synced to the IdP access-token row)
# --------------------------------------------------------------------------- #


class TestCookieAndAccessToken:
    async def test_create_cookie_token_round_trips(self, session) -> None:
        await _seed_user(session)
        await _seed_idp_rows(session)
        svc = _seeded_service(session)
        token = await svc.create_cookie_token(_TEST_USER_ID)
        auth = await svc.authenticate(token)
        assert auth.user_id == _TEST_USER_ID
        assert auth.token_type is TokenType.COOKIE
        assert auth.enabled is True
        # exp synced to the access-token row, not a config value.
        assert abs(auth.expires_at - _ACCESS_EXPIRES_AT) < timedelta(seconds=5)

    async def test_create_access_token_round_trips(self, session) -> None:
        await _seed_user(session)
        await _seed_idp_rows(session)
        svc = _seeded_service(session)
        token = await svc.create_access_token(_TEST_USER_ID)
        auth = await svc.authenticate(token)
        assert auth.token_type is TokenType.ACCESS_TOKEN
        assert auth.user_id == _TEST_USER_ID
        assert abs(auth.expires_at - _ACCESS_EXPIRES_AT) < timedelta(seconds=5)

    async def test_reissue_cookie_mints_fresh_cookie(self, session) -> None:
        await _seed_user(session)
        await _seed_idp_rows(session)
        svc = _seeded_service(session)
        first = await svc.create_cookie_token(_TEST_USER_ID)
        second = await svc.reissue_cookie(_TEST_USER_ID)
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

    async def test_mint_without_idp_row_raises(self, session) -> None:
        """Minting requires a federated grant to sync to."""
        await _seed_user(session)
        svc = _seeded_service(session)
        with pytest.raises(InvalidTokenError):
            await svc.create_access_token(_TEST_USER_ID)


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
        await _seed_idp_rows(session)
        svc = _seeded_service(session)
        refresh, _row_id = await svc.create_refresh_token(_TEST_USER_ID)
        with pytest.raises(InvalidTokenError):
            await svc.authenticate(refresh)

    async def test_refresh_token_accepted_with_allow_refresh(self, session) -> None:
        await _seed_user(session)
        await _seed_idp_rows(session)
        svc = _seeded_service(session)
        refresh, _row_id = await svc.create_refresh_token(_TEST_USER_ID)
        auth = await svc.authenticate(refresh, allow_refresh=True)
        assert auth.token_type is TokenType.IDP_REFRESH_TOKEN
        assert auth.enabled is True


# --------------------------------------------------------------------------- #
# API keys
# --------------------------------------------------------------------------- #


class TestApiKeys:
    async def test_create_and_authenticate_api_key(self, session) -> None:
        await _seed_user(session)
        svc = _seeded_service(session)
        plaintext, row = await svc.create_api_key(_TEST_USER_ID, name="ci-key")
        assert isinstance(row, ApiKey)
        assert row.name == "ci-key"
        assert row.api_key_hash  # persisted, not the plaintext
        assert len(row.api_key_hash) == 64
        assert row.key_prefix == plaintext[:12]
        auth = await svc.authenticate_api_key(plaintext)
        assert auth.token_type is TokenType.API_KEY
        assert auth.user_id == _TEST_USER_ID
        assert auth.enabled is True

    async def test_api_key_with_expiry_authenticates_until_expiry(self, session) -> None:
        await _seed_user(session)
        svc = _seeded_service(session)
        expires = datetime.now(UTC) + timedelta(hours=1)
        plaintext, _row = await svc.create_api_key(_TEST_USER_ID, expires_at=expires)
        auth = await svc.authenticate_api_key(plaintext)
        assert auth.enabled is True

    async def test_disabled_api_key_row_rejected(self, session) -> None:
        await _seed_user(session)
        svc = _seeded_service(session)
        plaintext, row = await svc.create_api_key(_TEST_USER_ID)
        row.enabled = False
        await session.flush()
        with pytest.raises(InvalidTokenError):
            await svc.authenticate_api_key(plaintext)

    async def test_deleted_api_key_row_rejected(self, session) -> None:
        await _seed_user(session)
        svc = _seeded_service(session)
        plaintext, row = await svc.create_api_key(_TEST_USER_ID)
        await session.delete(row)
        await session.flush()
        with pytest.raises(InvalidTokenError):
            await svc.authenticate_api_key(plaintext)

    async def test_unknown_api_key_rejected(self, session) -> None:
        await _seed_user(session)
        svc = _seeded_service(session)
        with pytest.raises(InvalidTokenError):
            await svc.authenticate_api_key("not-a-real-key")

    async def test_api_key_jwe_not_accepted_by_authenticate(self, session) -> None:
        """A JWE claiming ttyp=api_key is not a valid credential (opaque path only)."""
        from openhands.ev2.encryption.encryption_service import get_encryption_service

        await _seed_user(session)
        enc = get_encryption_service()
        bogus = enc.create_jwe_token(
            {
                "sub": str(_TEST_USER_ID),
                "ttyp": TokenType.API_KEY.value,
                "jti": str(uuid.uuid4()),
            },
            expires_in=timedelta(hours=1),
        )
        svc = _seeded_service(session)
        with pytest.raises(InvalidTokenError):
            await svc.authenticate(bogus)


# --------------------------------------------------------------------------- #
# Refresh-token minting (federated; rotation is covered by test_auth_service)
# --------------------------------------------------------------------------- #


class TestRefreshMinting:
    async def test_create_refresh_token_synced_to_idp_row(self, session) -> None:
        await _seed_user(session)
        await _seed_idp_rows(session)
        svc = _seeded_service(session)
        token, _row_id = await svc.create_refresh_token(_TEST_USER_ID)
        auth = await svc.authenticate(token, allow_refresh=True)
        assert auth.token_type is TokenType.IDP_REFRESH_TOKEN
        assert auth.enabled is True
        # exp synced to the IdP refresh-token row, not a config sliding window.
        assert abs(auth.expires_at - _REFRESH_EXPIRES_AT) < timedelta(seconds=5)

    async def test_create_refresh_token_revoked_row_rejected(self, session) -> None:
        """A refresh token backed by an expired IdP row authenticates as disabled."""
        await _seed_user(session)
        refresh_row, _ = await _seed_idp_rows(
            session, refresh_expires_at=datetime.now(UTC) - timedelta(seconds=1)
        )
        svc = _seeded_service(session)
        token, _row_id = await svc.create_refresh_token(_TEST_USER_ID)
        auth = await svc.authenticate(token, allow_refresh=True)
        assert auth.enabled is False
        _ = refresh_row  # the expired backing row


# --------------------------------------------------------------------------- #
# Backing-row helpers (direct)
# --------------------------------------------------------------------------- #


class TestBackingRows:
    async def test_load_api_key_by_plaintext(self, session) -> None:
        await _seed_user(session)
        svc = _seeded_service(session)
        plaintext, row = await svc.create_api_key(_TEST_USER_ID)
        loaded = await svc._load_api_key(plaintext)
        assert loaded is not None
        assert loaded.id == row.id

    async def test_load_api_key_false_for_missing(self, session) -> None:
        await _seed_user(session)
        svc = _seeded_service(session)
        assert await svc._load_api_key("not-a-real-key") is None

    async def test_idp_refresh_token_live_checks_row(self, session) -> None:
        await _seed_user(session)
        await _seed_idp_rows(session)
        svc = _seeded_service(session)
        _, row_id = await svc.create_refresh_token(_TEST_USER_ID)
        assert await svc._idp_refresh_token_live(row_id) is True

    async def test_idp_refresh_token_live_false_for_missing(self, session) -> None:
        await _seed_user(session)
        svc = _seeded_service(session)
        assert await svc._idp_refresh_token_live(uuid.uuid4()) is False


# --------------------------------------------------------------------------- #
# Decode error branches (defensive paths in payload helpers)
# --------------------------------------------------------------------------- #


class TestDecodeErrorBranches:
    async def test_refresh_token_missing_rid_rejected(self, session) -> None:
        """An IDP_REFRESH_TOKEN JWE without its rid claim fails validation."""
        from openhands.ev2.encryption.encryption_service import get_encryption_service

        await _seed_user(session)
        enc = get_encryption_service()
        bad = enc.create_jwe_token(
            {
                "sub": str(_TEST_USER_ID),
                "ttyp": "idp_refresh_token",
                "jti": str(uuid.uuid4()),
            },
            expires_in=timedelta(hours=1),
        )
        with pytest.raises(InvalidTokenError):
            await _seeded_service(session).authenticate(bad, allow_refresh=True)

    async def test_token_missing_type_rejected(self, session) -> None:
        from openhands.ev2.encryption.encryption_service import get_encryption_service

        enc = get_encryption_service()
        bad = enc.create_jwe_token({"sub": str(_TEST_USER_ID)}, expires_in=timedelta(hours=1))
        with pytest.raises(InvalidTokenError):
            await _seeded_service(session).authenticate(bad)

    async def test_token_unknown_type_rejected(self, session) -> None:
        from openhands.ev2.encryption.encryption_service import get_encryption_service

        enc = get_encryption_service()
        bad = enc.create_jwe_token(
            {"sub": str(_TEST_USER_ID), "ttyp": "bogus", "jti": str(uuid.uuid4())},
            expires_in=timedelta(hours=1),
        )
        with pytest.raises(InvalidTokenError):
            await _seeded_service(session).authenticate(bad)

    async def test_token_missing_subject_rejected(self, session) -> None:
        from openhands.ev2.encryption.encryption_service import get_encryption_service

        enc = get_encryption_service()
        bad = enc.create_jwe_token(
            {"ttyp": "cookie", "jti": str(uuid.uuid4())},
            expires_in=timedelta(hours=1),
        )
        with pytest.raises(InvalidTokenError):
            await _seeded_service(session).authenticate(bad)

    async def test_token_invalid_subject_rejected(self, session) -> None:
        from openhands.ev2.encryption.encryption_service import get_encryption_service

        enc = get_encryption_service()
        bad = enc.create_jwe_token(
            {"sub": "not-a-uuid", "ttyp": "cookie", "jti": str(uuid.uuid4())},
            expires_in=timedelta(hours=1),
        )
        with pytest.raises(InvalidTokenError):
            await _seeded_service(session).authenticate(bad)

    async def test_token_missing_jti_rejected(self, session) -> None:
        from openhands.ev2.encryption.encryption_service import get_encryption_service

        enc = get_encryption_service()
        bad = enc.create_jwe_token(
            {"sub": str(_TEST_USER_ID), "ttyp": "cookie"},
            expires_in=timedelta(hours=1),
        )
        with pytest.raises(InvalidTokenError):
            await _seeded_service(session).authenticate(bad)
