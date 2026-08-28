"""Tests for the auth2 service: IdP exchange, provisioning, token minting, cleanup.

The IdP HTTP endpoints are mocked with respx so the tests are hermetic. The
encryption service and config are the real singletons (pointed at a test DB
via conftest).
"""

from __future__ import annotations

import base64
import json
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import respx
from sqlalchemy import select

from openhands.ev2.auth.auth_models import TokenType
from openhands.ev2.auth2.auth2_models import (
    IdpAccessToken,
    IdpRefreshToken,
    OAuthClient,
    OAuthClientRedirectUri,
)
from openhands.ev2.auth2.auth2_service import (
    Auth2Error,
    Auth2Service,
    IdpError,
    InvalidClientError,
    InvalidGrantError,
    InvalidRedirectUriError,
    _claim,
    _decode_id_token,
    _derive_code_challenge,
    _generate_code_verifier,
    _idp_access_expiry,
    _idp_refresh_expiry,
    _wildcard_match,
)
from openhands.ev2.config import AppConfig, EncryptionKeyConfig
from openhands.ev2.encryption.encryption_service import get_encryption_service
from openhands.ev2.user.user_models import User

# asyncio_mode=auto (pyproject) marks async tests; sync helper tests need no mark.

_IDP_BASE = "https://idp.example.com"
_CALLBACK = "https://app.example.com/auth2/callback"


def _test_cfg() -> AppConfig:
    """A minimal AppConfig with the IdP + encryption fields required by the
    pure helper tests (which read config fallbacks for token expiries)."""
    from pydantic import SecretStr

    return AppConfig(  # type: ignore[call-arg]
        idp={
            "url": _IDP_BASE,
            "client_id": "test-client",
            "client_secret": SecretStr("test-secret"),
        },
        encryption_key=EncryptionKeyConfig(
            id="primary", value=SecretStr("test-secret-at-least-32-bytes-long!!")
        ),
    )


def _make_id_token(sub: str, email: str) -> str:
    """Build an unsigned id_token with the given claims (header.payload.)."""
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=").decode()
    payload = (
        base64.urlsafe_b64encode(json.dumps({"sub": sub, "email": email}).encode())
        .rstrip(b"=")
        .decode()
    )
    return f"{header}.{payload}."


def _idp_token_response(sub: str, email: str, refresh: str = "idp-refresh-1") -> dict:
    return {
        "access_token": "idp-access-1",
        "refresh_token": refresh,
        "expires_in": 3600,
        "id_token": _make_id_token(sub, email),
        "token_type": "Bearer",
    }


@pytest.fixture
def http_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(base_url=_IDP_BASE)


@pytest.fixture
async def service(session, http_client: httpx.AsyncClient) -> Auth2Service:
    s = Auth2Service(session, http_client=http_client)
    yield s
    # The session owns the lifecycle; do not close the injected client here.


async def _create_client(
    service: Auth2Service,
    *,
    client_id: str = "client-1",
    client_secret: str = "secret-1",
    redirect_uris: list[str] | None = None,
) -> OAuthClient:
    return await service.create_client(
        client_id=client_id,
        client_secret=client_secret,
        name="Test Client",
        redirect_uris=redirect_uris or ["https://app.example.com/cb"],
        enabled=True,
    )


# ---------------------------------------------------------------------------
# Pure helper functions
# ---------------------------------------------------------------------------


class TestHelpers:
    def test_wildcard_match_exact(self) -> None:
        assert _wildcard_match("https://app.example.com/cb", "https://app.example.com/cb")

    def test_wildcard_match_segment(self) -> None:
        assert _wildcard_match("https://*.example.com/cb", "https://app.example.com/cb")
        assert _wildcard_match("https://*.example.com/cb", "https://other.example.com/cb")

    def test_wildcard_mismatch(self) -> None:
        assert not _wildcard_match("https://app.example.com/cb", "https://app.example.com/other")
        assert not _wildcard_match("https://*.example.com/cb", "https://app.other.com/cb")

    def test_wildcard_matches_prefix(self) -> None:
        assert _wildcard_match("https://app.example.com/*", "https://app.example.com/cb")
        assert _wildcard_match("https://app.example.com/*", "https://app.example.com/any/path")

    def test_claim_uses_configured_name(self) -> None:
        claims = {"custom_sub": "u1", "sub": "u2"}
        assert _claim(claims, "custom_sub", "sub") == "u1"

    def test_claim_falls_back_to_default(self) -> None:
        claims = {"sub": "u2"}
        assert _claim(claims, None, "sub") == "u2"

    def test_claim_missing_returns_none(self) -> None:
        assert _claim({}, None, "sub") is None

    def test_claim_empty_string_returns_none(self) -> None:
        assert _claim({"sub": ""}, None, "sub") is None

    def test_decode_id_token_extracts_claims(self) -> None:
        token = _make_id_token("sub-1", "a@b.com")
        claims = _decode_id_token(token)
        assert claims["sub"] == "sub-1"
        assert claims["email"] == "a@b.com"

    def test_decode_id_token_garbage_returns_empty(self) -> None:
        assert _decode_id_token("not-a-jwt") == {}

    def test_generate_and_derive_code_challenge_s256(self) -> None:
        verifier = _generate_code_verifier()
        challenge = _derive_code_challenge(verifier, "S256")
        assert challenge != verifier
        assert _derive_code_challenge(verifier, "S256") == challenge

    def test_derive_code_challenge_plain(self) -> None:
        assert _derive_code_challenge("v", "plain") == "v"

    def test_idp_access_expiry_from_expires_in(self) -> None:
        cfg = _test_cfg()
        expiry = _idp_access_expiry({"expires_in": 3600}, drift_seconds=60, idp=cfg.idp)
        assert abs((expiry - datetime.now(UTC)).total_seconds() - 3540) < 5

    def test_idp_access_expiry_drift_floor_zero(self) -> None:
        cfg = _test_cfg()
        expiry = _idp_access_expiry({"expires_in": 30}, drift_seconds=60, idp=cfg.idp)
        # Drift subtracted but floored at 0 → expiry is ~now.
        assert abs((expiry - datetime.now(UTC)).total_seconds()) < 5

    def test_idp_access_expiry_default_when_missing(self) -> None:
        cfg = _test_cfg()
        expiry = _idp_access_expiry({}, drift_seconds=60, idp=cfg.idp)
        # Falls back to idp_access_token_expires_in (900) minus drift.
        assert abs((expiry - datetime.now(UTC)).total_seconds() - 840) < 5

    def test_idp_refresh_expiry_from_refresh_expires_in(self) -> None:
        cfg = _test_cfg()
        expiry = _idp_refresh_expiry({"refresh_expires_in": 86400}, drift_seconds=60, idp=cfg.idp)
        assert abs((expiry - datetime.now(UTC)).total_seconds() - 86340) < 5

    def test_idp_refresh_expiry_default_when_missing(self) -> None:
        cfg = _test_cfg()
        expiry = _idp_refresh_expiry({}, drift_seconds=60, idp=cfg.idp)
        # Falls back to idp_refresh_token_expires_in (30 days) minus drift.
        assert (expiry - datetime.now(UTC)).total_seconds() > 86000


# ---------------------------------------------------------------------------
# Client management
# ---------------------------------------------------------------------------


class TestClientManagement:
    async def test_create_client_encrypts_secret(self, service: Auth2Service) -> None:
        client = await _create_client(service)
        assert client.client_secret != "secret-1"
        # Decrypt round-trips.
        enc = get_encryption_service()
        assert enc.decrypt_value(client.client_secret) == "secret-1"

    async def test_list_redirect_uris(self, service: Auth2Service) -> None:
        client = await _create_client(service, redirect_uris=["https://a/cb", "https://b/cb"])
        uris = await service.list_redirect_uris(client)
        assert uris == ["https://a/cb", "https://b/cb"]

    async def test_replace_redirect_uris(self, service: Auth2Service) -> None:
        client = await _create_client(service, redirect_uris=["https://a/cb"])
        await service.replace_redirect_uris(client, ["https://c/cb", "https://d/cb"])
        assert await service.list_redirect_uris(client) == ["https://c/cb", "https://d/cb"]

    async def test_search_clients_pagination(self, service: Auth2Service) -> None:
        await _create_client(service, client_id="c1")
        await _create_client(service, client_id="c2")
        clients, next_cursor = await service.search_clients(limit=1)
        assert len(clients) == 1
        assert next_cursor is not None
        clients2, next_cursor2 = await service.search_clients(cursor=next_cursor, limit=1)
        assert len(clients2) == 1
        assert next_cursor2 is None

    async def test_delete_client_cascades_uris(self, service: Auth2Service) -> None:
        client = await _create_client(service, redirect_uris=["https://a/cb"])
        await service.delete_client(client)
        from sqlalchemy import select

        result = await service._session.execute(
            select(OAuthClientRedirectUri).where(OAuthClientRedirectUri.client_id == client.id)
        )
        assert result.scalars().all() == []

    async def test_authenticate_client_success(self, service: Auth2Service) -> None:
        await _create_client(service, client_id="c1", client_secret="s1")
        client = await service._authenticate_client("c1", "s1")
        assert client.client_id == "c1"

    async def test_authenticate_client_wrong_secret(self, service: Auth2Service) -> None:
        await _create_client(service, client_id="c1", client_secret="s1")
        with pytest.raises(InvalidClientError):
            await service._authenticate_client("c1", "wrong")

    async def test_authenticate_client_unknown(self, service: Auth2Service) -> None:
        with pytest.raises(InvalidClientError):
            await service._authenticate_client("nope", "s1")

    async def test_authenticate_client_disabled(self, service: Auth2Service) -> None:
        await _create_client(service, client_id="c1", client_secret="s1")
        # Disable the client directly.
        client = await service.get_client_by_client_id("c1")
        assert client is not None
        client.enabled = False
        await service._session.flush()
        with pytest.raises(InvalidClientError):
            await service._authenticate_client("c1", "s1")

    async def test_redirect_uri_allowed_wildcard(self, service: Auth2Service) -> None:
        client = await _create_client(service, redirect_uris=["https://*.example.com/cb"])
        assert await service._redirect_uri_allowed(client, "https://app.example.com/cb")
        assert not await service._redirect_uri_allowed(client, "https://app.other.com/cb")


# ---------------------------------------------------------------------------
# Authorize redirect
# ---------------------------------------------------------------------------


class TestAuthorizeRedirect:
    async def test_build_redirect_validates_client(self, service: Auth2Service) -> None:
        with pytest.raises(InvalidClientError):
            await service.build_authorize_redirect(
                client_id="unknown",
                redirect_uri="https://app.example.com/cb",
                state="st",
                scope=None,
                code_challenge=None,
                code_challenge_method=None,
                callback_url=_CALLBACK,
            )

    async def test_build_redirect_rejects_unlisted_uri(self, service: Auth2Service) -> None:
        await _create_client(service, redirect_uris=["https://app.example.com/cb"])
        with pytest.raises(InvalidRedirectUriError):
            await service.build_authorize_redirect(
                client_id="client-1",
                redirect_uri="https://evil.example.com/cb",
                state="st",
                scope=None,
                code_challenge=None,
                code_challenge_method=None,
                callback_url=_CALLBACK,
            )

    async def test_build_redirect_returns_idp_url(self, service: Auth2Service) -> None:
        await _create_client(service, redirect_uris=["https://app.example.com/cb"])
        url = await service.build_authorize_redirect(
            client_id="client-1",
            redirect_uri="https://app.example.com/cb",
            state="client-state",
            scope=None,
            code_challenge=None,
            code_challenge_method=None,
            callback_url=_CALLBACK,
        )
        assert url.startswith(f"{_IDP_BASE}/authorize?")
        assert "response_type=code" in url
        assert "code_challenge_method=S256" in url

    async def test_build_redirect_rejects_unsupported_response_type(
        self, service: Auth2Service
    ) -> None:
        # Defense in depth: the router's Literal guards this, but the service
        # also rejects an unsupported response_type before touching the client.
        await _create_client(service, redirect_uris=["https://app.example.com/cb"])
        with pytest.raises(Auth2Error):
            await service.build_authorize_redirect(
                client_id="client-1",
                redirect_uri="https://app.example.com/cb",
                state="st",
                scope=None,
                code_challenge=None,
                code_challenge_method=None,
                callback_url=_CALLBACK,
                response_type="bogus",
            )

    async def test_build_redirect_cookie_response_type_records_state(
        self, service: Auth2Service
    ) -> None:
        # response_type=cookie is accepted and round-trips through the
        # pending-auth state so the callback knows to skip the code.
        from urllib.parse import parse_qs, urlparse

        await _create_client(service, redirect_uris=["https://app.example.com/cb"])
        url = await service.build_authorize_redirect(
            client_id="client-1",
            redirect_uri="https://app.example.com/cb",
            state=None,
            scope=None,
            code_challenge=None,
            code_challenge_method=None,
            callback_url=_CALLBACK,
            response_type="cookie",
        )
        state = parse_qs(urlparse(url).query)["state"][0]
        pending = service._decode_pending_auth(state)
        assert pending["response_type"] == "cookie"


# ---------------------------------------------------------------------------
# Callback → code exchange → provisioning
# ---------------------------------------------------------------------------


class TestCallback:
    @respx.mock
    async def test_callback_provisions_user_and_persists_refresh(
        self, service: Auth2Service
    ) -> None:
        await _create_client(service, redirect_uris=["https://app.example.com/cb"])
        # Build a real authorize redirect to get a valid pending-auth state.
        url = await service.build_authorize_redirect(
            client_id="client-1",
            redirect_uri="https://app.example.com/cb",
            state="client-state",
            scope=None,
            code_challenge=None,
            code_challenge_method=None,
            callback_url=_CALLBACK,
        )
        from urllib.parse import parse_qs, urlparse

        state = parse_qs(urlparse(url).query)["state"][0]

        respx.post(f"{_IDP_BASE}/token").mock(
            return_value=httpx.Response(
                200, json=_idp_token_response("idp-sub-1", "alice@example.com")
            )
        )
        ctx = await service.handle_callback(code="idp-code", state=state, callback_url=_CALLBACK)
        await service._session.commit()

        assert ctx.client_id == "client-1"
        assert ctx.redirect_uri == "https://app.example.com/cb"
        assert ctx.client_state == "client-state"

        # User JIT-provisioned with the IdP subject linked.
        from sqlalchemy import select

        user = (
            await service._session.execute(select(User).where(User.idp_user_id == "idp-sub-1"))
        ).scalar_one()
        assert user.email == "alice@example.com"
        assert user.enabled

        # Encrypted refresh token persisted.
        row = (
            await service._session.execute(
                select(IdpRefreshToken).where(IdpRefreshToken.user_id == user.id)
            )
        ).scalar_one()
        enc = get_encryption_service()
        assert enc.decrypt_value(row.refresh_token) == "idp-refresh-1"
        assert row.expires_at > datetime.now(UTC)

    @respx.mock
    async def test_callback_links_existing_user_by_email(self, service: Auth2Service) -> None:
        # Pre-existing local user without an IdP link.
        existing = User(email="bob@example.com", username="bob", enabled=True, idp_user_id=None)
        service._session.add(existing)
        await service._session.flush()

        await _create_client(service, redirect_uris=["https://app.example.com/cb"])
        url = await service.build_authorize_redirect(
            client_id="client-1",
            redirect_uri="https://app.example.com/cb",
            state=None,
            scope=None,
            code_challenge=None,
            code_challenge_method=None,
            callback_url=_CALLBACK,
        )
        from urllib.parse import parse_qs, urlparse

        state = parse_qs(urlparse(url).query)["state"][0]
        respx.post(f"{_IDP_BASE}/token").mock(
            return_value=httpx.Response(
                200, json=_idp_token_response("idp-sub-2", "bob@example.com")
            )
        )
        ctx = await service.handle_callback(code="idp-code", state=state, callback_url=_CALLBACK)
        await service._session.commit()
        assert ctx.user_id == existing.id
        await service._session.refresh(existing)
        assert existing.idp_user_id == "idp-sub-2"

    @respx.mock
    async def test_callback_looks_up_existing_user_by_idp_id(self, service: Auth2Service) -> None:
        existing = User(
            email="carol@example.com",
            username="carol",
            enabled=True,
            idp_user_id="idp-sub-3",
        )
        service._session.add(existing)
        await service._session.flush()

        await _create_client(service, redirect_uris=["https://app.example.com/cb"])
        url = await service.build_authorize_redirect(
            client_id="client-1",
            redirect_uri="https://app.example.com/cb",
            state=None,
            scope=None,
            code_challenge=None,
            code_challenge_method=None,
            callback_url=_CALLBACK,
        )
        from urllib.parse import parse_qs, urlparse

        state = parse_qs(urlparse(url).query)["state"][0]
        respx.post(f"{_IDP_BASE}/token").mock(
            return_value=httpx.Response(
                200, json=_idp_token_response("idp-sub-3", "carol@example.com")
            )
        )
        ctx = await service.handle_callback(code="idp-code", state=state, callback_url=_CALLBACK)
        await service._session.commit()
        assert ctx.user_id == existing.id

    async def test_callback_bad_state_rejected(self, service: Auth2Service) -> None:
        with pytest.raises(InvalidGrantError):
            await service.handle_callback(code="idp-code", state="garbage", callback_url=_CALLBACK)

    @respx.mock
    async def test_callback_idp_error_raises(self, service: Auth2Service) -> None:
        await _create_client(service, redirect_uris=["https://app.example.com/cb"])
        url = await service.build_authorize_redirect(
            client_id="client-1",
            redirect_uri="https://app.example.com/cb",
            state=None,
            scope=None,
            code_challenge=None,
            code_challenge_method=None,
            callback_url=_CALLBACK,
        )
        from urllib.parse import parse_qs, urlparse

        state = parse_qs(urlparse(url).query)["state"][0]
        respx.post(f"{_IDP_BASE}/token").mock(return_value=httpx.Response(500))
        with pytest.raises(IdpError):
            await service.handle_callback(code="idp-code", state=state, callback_url=_CALLBACK)

    @respx.mock
    async def test_callback_missing_refresh_token_raises(self, service: Auth2Service) -> None:
        await _create_client(service, redirect_uris=["https://app.example.com/cb"])
        url = await service.build_authorize_redirect(
            client_id="client-1",
            redirect_uri="https://app.example.com/cb",
            state=None,
            scope=None,
            code_challenge=None,
            code_challenge_method=None,
            callback_url=_CALLBACK,
        )
        from urllib.parse import parse_qs, urlparse

        state = parse_qs(urlparse(url).query)["state"][0]
        # No refresh_token in the response.
        respx.post(f"{_IDP_BASE}/token").mock(
            return_value=httpx.Response(
                200,
                json={"access_token": "a", "id_token": _make_id_token("s", "e@x.com")},
            )
        )
        with pytest.raises(IdpError):
            await service.handle_callback(code="idp-code", state=state, callback_url=_CALLBACK)

    @respx.mock
    async def test_cookie_flow_provisions_without_minting_code(self, service: Auth2Service) -> None:
        # response_type=cookie: the callback provisions the user and persists
        # the IdP refresh token, but does NOT mint an authorization code.
        await _create_client(service, redirect_uris=["https://app.example.com/cb"])
        url = await service.build_authorize_redirect(
            client_id="client-1",
            redirect_uri="https://app.example.com/cb",
            state="client-state",
            scope=None,
            code_challenge=None,
            code_challenge_method=None,
            callback_url=_CALLBACK,
            response_type="cookie",
        )
        from urllib.parse import parse_qs, urlparse

        state = parse_qs(urlparse(url).query)["state"][0]
        respx.post(f"{_IDP_BASE}/token").mock(
            return_value=httpx.Response(
                200, json=_idp_token_response("cookie-sub", "cookie@example.com")
            )
        )
        ctx = await service.handle_callback(code="idp-code", state=state, callback_url=_CALLBACK)
        await service._session.commit()

        assert ctx.response_type == "cookie"
        assert ctx.auth_code is None
        assert ctx.client_state == "client-state"
        # User still JIT-provisioned and refresh token still persisted.
        from sqlalchemy import select

        user = (
            await service._session.execute(select(User).where(User.idp_user_id == "cookie-sub"))
        ).scalar_one()
        assert user.email == "cookie@example.com"
        row = (
            await service._session.execute(
                select(IdpRefreshToken).where(IdpRefreshToken.user_id == user.id)
            )
        ).scalar_one()
        assert get_encryption_service().decrypt_value(row.refresh_token) == "idp-refresh-1"

    @respx.mock
    async def test_cookie_flow_refresh_still_works(self, service: Auth2Service) -> None:
        # The cookie flow still persists a refresh-token row, so the refresh
        # grant remains usable even though no code was minted.
        await _create_client(service, redirect_uris=["https://app.example.com/cb"])
        url = await service.build_authorize_redirect(
            client_id="client-1",
            redirect_uri="https://app.example.com/cb",
            state=None,
            scope=None,
            code_challenge=None,
            code_challenge_method=None,
            callback_url=_CALLBACK,
            response_type="cookie",
        )
        from urllib.parse import parse_qs, urlparse

        state = parse_qs(urlparse(url).query)["state"][0]
        respx.post(f"{_IDP_BASE}/token").mock(
            return_value=httpx.Response(
                200, json=_idp_token_response("cookie-refresh-sub", "cr@example.com")
            )
        )
        ctx = await service.handle_callback(code="idp-code", state=state, callback_url=_CALLBACK)
        await service._session.commit()
        assert ctx.auth_code is None

        # Mint a refresh token directly off the persisted row (the cookie flow
        # never produces one via /token), then exercise the refresh grant.
        refresh_row = (
            await service._session.execute(
                select(IdpRefreshToken).where(IdpRefreshToken.id == ctx.row_id)
            )
        ).scalar_one()
        refresh_token = service._mint_refresh_token(ctx.user_id, refresh_row)
        respx.post(f"{_IDP_BASE}/token").mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": "idp-access-2",
                    "refresh_token": "idp-refresh-2",
                    "expires_in": 3600,
                    "token_type": "Bearer",
                },
            )
        )
        pair = await service.exchange_refresh_token(
            refresh_token=refresh_token,
            client_id="client-1",
            client_secret="secret-1",
        )
        assert pair.access_token
        assert pair.refresh_token


# ---------------------------------------------------------------------------
# Full flow: callback → token exchange → refresh
# ---------------------------------------------------------------------------


class TestTokenExchange:
    @respx.mock
    async def test_full_flow_auth_code_grant(self, service: Auth2Service) -> None:
        await _create_client(service, redirect_uris=["https://app.example.com/cb"])
        url = await service.build_authorize_redirect(
            client_id="client-1",
            redirect_uri="https://app.example.com/cb",
            state=None,
            scope=None,
            code_challenge=None,
            code_challenge_method=None,
            callback_url=_CALLBACK,
        )
        from urllib.parse import parse_qs, urlparse

        state = parse_qs(urlparse(url).query)["state"][0]
        respx.post(f"{_IDP_BASE}/token").mock(
            return_value=httpx.Response(
                200, json=_idp_token_response("idp-sub-1", "alice@example.com")
            )
        )
        ctx = await service.handle_callback(code="idp-code", state=state, callback_url=_CALLBACK)
        await service._session.commit()

        pair = await service.exchange_authorization_code(
            code=ctx.auth_code,
            redirect_uri="https://app.example.com/cb",
            client_id="client-1",
            client_secret="secret-1",
            code_verifier=None,
        )
        await service._session.commit()
        assert pair.access_token
        assert pair.refresh_token
        assert pair.expires_in > 0

        # The access token decrypts as an access_token type.
        enc = get_encryption_service()
        payload = enc.decrypt_jwe_token(pair.access_token)
        assert payload["ttyp"] == TokenType.ACCESS_TOKEN.value

    @respx.mock
    async def test_auth_code_wrong_client_secret_rejected(self, service: Auth2Service) -> None:
        await _create_client(service, redirect_uris=["https://app.example.com/cb"])
        url = await service.build_authorize_redirect(
            client_id="client-1",
            redirect_uri="https://app.example.com/cb",
            state=None,
            scope=None,
            code_challenge=None,
            code_challenge_method=None,
            callback_url=_CALLBACK,
        )
        from urllib.parse import parse_qs, urlparse

        state = parse_qs(urlparse(url).query)["state"][0]
        respx.post(f"{_IDP_BASE}/token").mock(
            return_value=httpx.Response(
                200, json=_idp_token_response("idp-sub-1", "alice@example.com")
            )
        )
        ctx = await service.handle_callback(code="idp-code", state=state, callback_url=_CALLBACK)
        await service._session.commit()
        with pytest.raises(InvalidClientError):
            await service.exchange_authorization_code(
                code=ctx.auth_code,
                redirect_uri="https://app.example.com/cb",
                client_id="client-1",
                client_secret="wrong",
                code_verifier=None,
            )

    @respx.mock
    async def test_auth_code_redirect_uri_mismatch_rejected(self, service: Auth2Service) -> None:
        await _create_client(service, redirect_uris=["https://app.example.com/cb"])
        url = await service.build_authorize_redirect(
            client_id="client-1",
            redirect_uri="https://app.example.com/cb",
            state=None,
            scope=None,
            code_challenge=None,
            code_challenge_method=None,
            callback_url=_CALLBACK,
        )
        from urllib.parse import parse_qs, urlparse

        state = parse_qs(urlparse(url).query)["state"][0]
        respx.post(f"{_IDP_BASE}/token").mock(
            return_value=httpx.Response(
                200, json=_idp_token_response("idp-sub-1", "alice@example.com")
            )
        )
        ctx = await service.handle_callback(code="idp-code", state=state, callback_url=_CALLBACK)
        await service._session.commit()
        with pytest.raises(InvalidGrantError, match="redirect_uri"):
            await service.exchange_authorization_code(
                code=ctx.auth_code,
                redirect_uri="https://evil.example.com/cb",
                client_id="client-1",
                client_secret="secret-1",
                code_verifier=None,
            )

    @respx.mock
    async def test_refresh_grant_rotates_via_idp(self, service: Auth2Service) -> None:
        await _create_client(service, redirect_uris=["https://app.example.com/cb"])
        url = await service.build_authorize_redirect(
            client_id="client-1",
            redirect_uri="https://app.example.com/cb",
            state=None,
            scope=None,
            code_challenge=None,
            code_challenge_method=None,
            callback_url=_CALLBACK,
        )
        from urllib.parse import parse_qs, urlparse

        state = parse_qs(urlparse(url).query)["state"][0]
        respx.post(f"{_IDP_BASE}/token").mock(
            return_value=httpx.Response(
                200, json=_idp_token_response("idp-sub-1", "alice@example.com")
            )
        )
        ctx = await service.handle_callback(code="idp-code", state=state, callback_url=_CALLBACK)
        await service._session.commit()
        pair = await service.exchange_authorization_code(
            code=ctx.auth_code,
            redirect_uri="https://app.example.com/cb",
            client_id="client-1",
            client_secret="secret-1",
            code_verifier=None,
        )
        await service._session.commit()

        # IdP rotates the refresh token on refresh.
        respx.post(f"{_IDP_BASE}/token").mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": "idp-access-2",
                    "refresh_token": "idp-refresh-2",
                    "expires_in": 3600,
                    "token_type": "Bearer",
                },
            )
        )
        pair2 = await service.exchange_refresh_token(
            refresh_token=pair.refresh_token,
            client_id="client-1",
            client_secret="secret-1",
        )
        await service._session.commit()
        assert pair2.access_token != pair.access_token
        assert pair2.refresh_token != pair.refresh_token

        # The persisted row now holds the rotated IdP refresh token.
        from sqlalchemy import select

        row = (
            await service._session.execute(
                select(IdpRefreshToken).where(IdpRefreshToken.user_id == ctx.user_id)
            )
        ).scalar_one()
        enc = get_encryption_service()
        assert enc.decrypt_value(row.refresh_token) == "idp-refresh-2"

    async def test_refresh_bad_token_rejected(self, service: Auth2Service) -> None:
        await _create_client(service, client_id="c1", client_secret="s1")
        with pytest.raises(InvalidGrantError):
            await service.exchange_refresh_token(
                refresh_token="garbage",
                client_id="c1",
                client_secret="s1",
            )

    @respx.mock
    async def test_refresh_expired_row_rejected(self, service: Auth2Service) -> None:
        await _create_client(service, redirect_uris=["https://app.example.com/cb"])
        url = await service.build_authorize_redirect(
            client_id="client-1",
            redirect_uri="https://app.example.com/cb",
            state=None,
            scope=None,
            code_challenge=None,
            code_challenge_method=None,
            callback_url=_CALLBACK,
        )
        from urllib.parse import parse_qs, urlparse

        state = parse_qs(urlparse(url).query)["state"][0]
        respx.post(f"{_IDP_BASE}/token").mock(
            return_value=httpx.Response(
                200, json=_idp_token_response("idp-sub-1", "alice@example.com")
            )
        )
        ctx = await service.handle_callback(code="idp-code", state=state, callback_url=_CALLBACK)
        await service._session.commit()
        pair = await service.exchange_authorization_code(
            code=ctx.auth_code,
            redirect_uri="https://app.example.com/cb",
            client_id="client-1",
            client_secret="secret-1",
            code_verifier=None,
        )
        await service._session.commit()
        # Expire the backing row.
        from sqlalchemy import select

        row = (
            await service._session.execute(
                select(IdpRefreshToken).where(IdpRefreshToken.user_id == ctx.user_id)
            )
        ).scalar_one()
        row.expires_at = datetime.now(UTC) - timedelta(hours=1)
        await service._session.commit()
        with pytest.raises(InvalidGrantError, match="expired"):
            await service.exchange_refresh_token(
                refresh_token=pair.refresh_token,
                client_id="client-1",
                client_secret="secret-1",
            )


# ---------------------------------------------------------------------------
# PKCE
# ---------------------------------------------------------------------------


class TestPkce:
    @respx.mock
    async def test_pkce_challenge_verified(self, service: Auth2Service) -> None:
        await _create_client(service, redirect_uris=["https://app.example.com/cb"])
        verifier = _generate_code_verifier()
        challenge = _derive_code_challenge(verifier, "S256")
        url = await service.build_authorize_redirect(
            client_id="client-1",
            redirect_uri="https://app.example.com/cb",
            state=None,
            scope=None,
            code_challenge=challenge,
            code_challenge_method="S256",
            callback_url=_CALLBACK,
        )
        from urllib.parse import parse_qs, urlparse

        state = parse_qs(urlparse(url).query)["state"][0]
        respx.post(f"{_IDP_BASE}/token").mock(
            return_value=httpx.Response(
                200, json=_idp_token_response("idp-sub-1", "alice@example.com")
            )
        )
        ctx = await service.handle_callback(code="idp-code", state=state, callback_url=_CALLBACK)
        await service._session.commit()
        # Correct verifier succeeds.
        pair = await service.exchange_authorization_code(
            code=ctx.auth_code,
            redirect_uri="https://app.example.com/cb",
            client_id="client-1",
            client_secret="secret-1",
            code_verifier=verifier,
        )
        await service._session.commit()
        assert pair.access_token

    @respx.mock
    async def test_pkce_wrong_verifier_rejected(self, service: Auth2Service) -> None:
        await _create_client(service, redirect_uris=["https://app.example.com/cb"])
        verifier = _generate_code_verifier()
        challenge = _derive_code_challenge(verifier, "S256")
        url = await service.build_authorize_redirect(
            client_id="client-1",
            redirect_uri="https://app.example.com/cb",
            state=None,
            scope=None,
            code_challenge=challenge,
            code_challenge_method="S256",
            callback_url=_CALLBACK,
        )
        from urllib.parse import parse_qs, urlparse

        state = parse_qs(urlparse(url).query)["state"][0]
        respx.post(f"{_IDP_BASE}/token").mock(
            return_value=httpx.Response(
                200, json=_idp_token_response("idp-sub-1", "alice@example.com")
            )
        )
        ctx = await service.handle_callback(code="idp-code", state=state, callback_url=_CALLBACK)
        await service._session.commit()
        with pytest.raises(InvalidGrantError, match="PKCE"):
            await service.exchange_authorization_code(
                code=ctx.auth_code,
                redirect_uri="https://app.example.com/cb",
                client_id="client-1",
                client_secret="secret-1",
                code_verifier="wrong-verifier",
            )

    @respx.mock
    async def test_pkce_missing_verifier_rejected(self, service: Auth2Service) -> None:
        await _create_client(service, redirect_uris=["https://app.example.com/cb"])
        verifier = _generate_code_verifier()
        challenge = _derive_code_challenge(verifier, "S256")
        url = await service.build_authorize_redirect(
            client_id="client-1",
            redirect_uri="https://app.example.com/cb",
            state=None,
            scope=None,
            code_challenge=challenge,
            code_challenge_method="S256",
            callback_url=_CALLBACK,
        )
        from urllib.parse import parse_qs, urlparse

        state = parse_qs(urlparse(url).query)["state"][0]
        respx.post(f"{_IDP_BASE}/token").mock(
            return_value=httpx.Response(
                200, json=_idp_token_response("idp-sub-1", "alice@example.com")
            )
        )
        ctx = await service.handle_callback(code="idp-code", state=state, callback_url=_CALLBACK)
        await service._session.commit()
        with pytest.raises(InvalidGrantError, match="code_verifier"):
            await service.exchange_authorization_code(
                code=ctx.auth_code,
                redirect_uri="https://app.example.com/cb",
                client_id="client-1",
                client_secret="secret-1",
                code_verifier=None,
            )


# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------


class TestCleanup:
    async def test_delete_expired_removes_old_rows(self, service: Auth2Service) -> None:
        enc = get_encryption_service()
        # A user to attach rows to.
        user = User(email="x@example.com", username="x", enabled=True)
        service._session.add(user)
        await service._session.flush()
        old = IdpRefreshToken(
            user_id=user.id,
            refresh_token=enc.encrypt_value("r1"),
            expires_at=datetime.now(UTC) - timedelta(days=2),
        )
        fresh = IdpRefreshToken(
            user_id=user.id,
            refresh_token=enc.encrypt_value("r2"),
            expires_at=datetime.now(UTC) + timedelta(days=1),
        )
        service._session.add_all([old, fresh])
        await service._session.commit()

        deleted = await service.delete_expired_tokens()
        assert deleted == 1
        from sqlalchemy import select

        remaining = (
            (
                await service._session.execute(
                    select(IdpRefreshToken).where(IdpRefreshToken.user_id == user.id)
                )
            )
            .scalars()
            .all()
        )
        assert len(remaining) == 1
        assert enc.decrypt_value(remaining[0].refresh_token) == "r2"

    async def test_delete_expired_respects_age_window(self, service: Auth2Service) -> None:
        enc = get_encryption_service()
        user = User(email="y@example.com", username="y", enabled=True)
        service._session.add(user)
        await service._session.flush()
        # Expired 1 hour ago — within the default 86400s window, so kept.
        recent = IdpRefreshToken(
            user_id=user.id,
            refresh_token=enc.encrypt_value("r"),
            expires_at=datetime.now(UTC) - timedelta(hours=1),
        )
        service._session.add(recent)
        await service._session.commit()
        deleted = await service.delete_expired_tokens()
        assert deleted == 0


# ---------------------------------------------------------------------------
# Cookie auto-refresh — refresh_access_token + row lock + mint_session_cookie.
# ---------------------------------------------------------------------------


class TestCookieAutoRefresh:
    """Cover the cookie-flow refresh path (Auth2Service.refresh_access_token,
    _refresh_rows_if_needed, mint_session_cookie) and the IdpAccessToken row
    persistence introduced for the federated access-token storage."""

    @respx.mock
    async def test_persists_access_token_row_on_callback(self, service: Auth2Service) -> None:
        """A cookie-flow callback persists both a refresh row and an access
        row, joined by refresh_token_id."""
        await _create_client(service, redirect_uris=[_CALLBACK])
        url = await service.build_authorize_redirect(
            client_id="client-1",
            redirect_uri=_CALLBACK,
            state=None,
            scope=None,
            code_challenge=None,
            code_challenge_method=None,
            callback_url=_CALLBACK,
            response_type="cookie",
        )
        from urllib.parse import parse_qs, urlparse

        state = parse_qs(urlparse(url).query)["state"][0]
        respx.post(f"{_IDP_BASE}/token").mock(
            return_value=httpx.Response(200, json=_idp_token_response("ct-sub", "ct@example.com"))
        )
        ctx = await service.handle_callback(code="idp-code", state=state, callback_url=_CALLBACK)
        await service._session.commit()

        access_row = (
            await service._session.execute(
                select(IdpAccessToken).where(IdpAccessToken.id == ctx.access_id)
            )
        ).scalar_one()
        assert access_row.refresh_token_id == ctx.row_id
        enc = get_encryption_service()
        assert enc.decrypt_value(access_row.access_token) == "idp-access-1"
        assert access_row.expires_at > datetime.now(UTC)

    @respx.mock
    async def test_refresh_access_token_refreshes_when_expired(self, service: Auth2Service) -> None:
        """When the access row has expired, refresh_access_token performs the
        IdP refresh and rewrites both rows with the rotated tokens."""
        await _create_client(service, redirect_uris=[_CALLBACK])
        url = await service.build_authorize_redirect(
            client_id="client-1",
            redirect_uri=_CALLBACK,
            state=None,
            scope=None,
            code_challenge=None,
            code_challenge_method=None,
            callback_url=_CALLBACK,
            response_type="cookie",
        )
        from urllib.parse import parse_qs, urlparse

        state = parse_qs(urlparse(url).query)["state"][0]
        respx.post(f"{_IDP_BASE}/token").mock(
            return_value=httpx.Response(200, json=_idp_token_response("ct-sub", "ct@example.com"))
        )
        ctx = await service.handle_callback(code="idp-code", state=state, callback_url=_CALLBACK)
        await service._session.commit()

        # Force the access row to be expired so refresh_access_token hits the IdP.
        access_row = (
            await service._session.execute(
                select(IdpAccessToken).where(IdpAccessToken.id == ctx.access_id)
            )
        ).scalar_one()
        access_row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        await service._session.commit()

        respx.post(f"{_IDP_BASE}/token").mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": "idp-access-2",
                    "refresh_token": "idp-refresh-2",
                    "expires_in": 3600,
                    "token_type": "Bearer",
                },
            )
        )
        new_access, new_refresh = await service.refresh_access_token(ctx.access_id)
        assert new_access.id == ctx.access_id
        enc = get_encryption_service()
        assert enc.decrypt_value(new_access.access_token) == "idp-access-2"
        assert enc.decrypt_value(new_refresh.refresh_token) == "idp-refresh-2"
        assert new_access.expires_at > datetime.now(UTC)

    @respx.mock
    async def test_refresh_access_token_skips_when_not_expired(self, service: Auth2Service) -> None:
        """When the access row is still valid, refresh_access_token does not
        call the IdP (no refresh needed)."""
        await _create_client(service, redirect_uris=[_CALLBACK])
        url = await service.build_authorize_redirect(
            client_id="client-1",
            redirect_uri=_CALLBACK,
            state=None,
            scope=None,
            code_challenge=None,
            code_challenge_method=None,
            callback_url=_CALLBACK,
            response_type="cookie",
        )
        from urllib.parse import parse_qs, urlparse

        state = parse_qs(urlparse(url).query)["state"][0]
        respx.post(f"{_IDP_BASE}/token").mock(
            return_value=httpx.Response(200, json=_idp_token_response("ct-sub", "ct@example.com"))
        )
        ctx = await service.handle_callback(code="idp-code", state=state, callback_url=_CALLBACK)
        await service._session.commit()

        # The IdP token endpoint should not be called again.
        respx.post(f"{_IDP_BASE}/token").mock(
            side_effect=AssertionError("IdP refresh should not be called")
        )
        new_access, _ = await service.refresh_access_token(ctx.access_id)
        assert new_access.id == ctx.access_id

    @respx.mock
    async def test_refresh_access_token_expired_refresh_raises(self, service: Auth2Service) -> None:
        """When the backing refresh row has expired, refresh_access_token
        raises InvalidGrantError (the user must re-authenticate)."""
        await _create_client(service, redirect_uris=[_CALLBACK])
        url = await service.build_authorize_redirect(
            client_id="client-1",
            redirect_uri=_CALLBACK,
            state=None,
            scope=None,
            code_challenge=None,
            code_challenge_method=None,
            callback_url=_CALLBACK,
            response_type="cookie",
        )
        from urllib.parse import parse_qs, urlparse

        state = parse_qs(urlparse(url).query)["state"][0]
        respx.post(f"{_IDP_BASE}/token").mock(
            return_value=httpx.Response(200, json=_idp_token_response("ct-sub", "ct@example.com"))
        )
        ctx = await service.handle_callback(code="idp-code", state=state, callback_url=_CALLBACK)
        await service._session.commit()

        refresh_row = (
            await service._session.execute(
                select(IdpRefreshToken).where(IdpRefreshToken.id == ctx.row_id)
            )
        ).scalar_one()
        refresh_row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        await service._session.commit()

        with pytest.raises(InvalidGrantError):
            await service.refresh_access_token(ctx.access_id)

    async def test_refresh_access_token_unknown_id_raises(self, service: Auth2Service) -> None:
        with pytest.raises(InvalidGrantError):
            await service.refresh_access_token(uuid.uuid4())

    @respx.mock
    async def test_mint_session_cookie_carries_synced_expiry(self, service: Auth2Service) -> None:
        """The cookie JWE carries the access row id + expiry so the auth
        dependency can detect imminent expiry."""
        await _create_client(service, redirect_uris=[_CALLBACK])
        url = await service.build_authorize_redirect(
            client_id="client-1",
            redirect_uri=_CALLBACK,
            state=None,
            scope=None,
            code_challenge=None,
            code_challenge_method=None,
            callback_url=_CALLBACK,
            response_type="cookie",
        )
        from urllib.parse import parse_qs, urlparse

        state = parse_qs(urlparse(url).query)["state"][0]
        respx.post(f"{_IDP_BASE}/token").mock(
            return_value=httpx.Response(200, json=_idp_token_response("ct-sub", "ct@example.com"))
        )
        ctx = await service.handle_callback(code="idp-code", state=state, callback_url=_CALLBACK)
        await service._session.commit()

        access_row = (
            await service._session.execute(
                select(IdpAccessToken).where(IdpAccessToken.id == ctx.access_id)
            )
        ).scalar_one()
        cookie = service.mint_session_cookie(ctx.user_id, access_row)
        enc = get_encryption_service()
        payload = enc.decrypt_jwe_token(cookie)
        assert payload["aid"] == str(ctx.access_id)
        assert int(payload["axp"]) == int(access_row.expires_at.timestamp())
