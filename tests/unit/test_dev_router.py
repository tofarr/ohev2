"""Route + service tests for the built-in dev identity provider (/auth/dev).

The dev router is mounted only when ``OHE_IDP_URL == "/auth/dev"``; these tests
build a dedicated app fixture with that config so the dev IdP endpoints are live,
then exercise them directly via the ASGI client and the DevIdpService.
"""

from __future__ import annotations

import base64
import json
import uuid
from collections.abc import AsyncGenerator
from urllib.parse import parse_qs, urlparse

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from pytest_postgresql.executor import PostgreSQLExecutor
from pytest_postgresql.janitor import DatabaseJanitor
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from openhands.ev2.app import create_app
from openhands.ev2.auth.auth_models import OAuthClient
from openhands.ev2.auth.dev_router import DevIdpService
from openhands.ev2.config import get_config
from openhands.ev2.cors.cors_models import AllowedOrigin  # noqa: F401
from openhands.ev2.db import dispose_engine_factory
from openhands.ev2.db import get_session as _app_get_session
from openhands.ev2.user.user_models import User  # noqa: F401
from openhands.ev2.util.password import hash_password

_DEV_USER_USERNAME = "dev-user"
_DEV_USER_PASSWORD = "dev-pass"


def _set_dev_config(
    monkeypatch: pytest.MonkeyPatch,
    *,
    host: str | None = None,
    port: str | None = None,
    db_name: str | None = None,
    username: str | None = None,
    password: str | None = None,
) -> None:
    """Point AppConfig at the dev test DB and select the dev IdP.

    DB coordinates are optional: callers that already set them via
    ``dev_engine`` omit them to keep the prior values.
    """
    get_config.cache_clear()
    monkeypatch.setenv("OHE_ENCRYPTION_KEY_VALUE", "test-secret-at-least-32-bytes-long!!")
    if host is not None:
        monkeypatch.setenv("OHE_DB_CONFIG_HOST", host)
    if port is not None:
        monkeypatch.setenv("OHE_DB_CONFIG_PORT", port)
    if db_name is not None:
        monkeypatch.setenv("OHE_DB_CONFIG_DB_NAME", db_name)
    if username is not None:
        monkeypatch.setenv("OHE_DB_CONFIG_USERNAME", username)
    if password is not None:
        monkeypatch.setenv("OHE_DB_CONFIG_PASSWORD", password)
    # Select the built-in dev identity provider.
    monkeypatch.setenv("OHE_IDP_URL", "/auth/dev")
    monkeypatch.setenv("OHE_IDP_CLIENT_ID", "ohe")
    monkeypatch.setenv("OHE_IDP_CLIENT_SECRET", "changeme")
    monkeypatch.setenv("OHE_BASE_URL", "http://test")
    monkeypatch.setenv("OHE_CLEANUP_INTERVAL", "0")


async def _seed_dev_user(engine: create_async_engine) -> uuid.UUID:
    """Insert an enabled user with a hashed password for /authorize auth."""
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as s:
        await s.execute(
            text(
                "INSERT INTO users (id, email, username, enabled, password) "
                "VALUES (:id, :email, :username, true, :password) "
                "ON CONFLICT (username) DO UPDATE SET password = EXCLUDED.password, "
                "enabled = true"
            ),
            {
                "id": uuid.UUID("11111111-1111-1111-1111-111111111111"),
                "email": "dev@example.com",
                "username": _DEV_USER_USERNAME,
                "password": hash_password(_DEV_USER_PASSWORD),
            },
        )
        await s.commit()
    return uuid.UUID("11111111-1111-1111-1111-111111111111")


@pytest_asyncio.fixture
async def dev_engine(
    monkeypatch: pytest.MonkeyPatch,
    pg_server: PostgreSQLExecutor,
) -> AsyncGenerator[AsyncEngine, None]:
    """A per-test engine on a fresh DB cloned from the session template."""
    proc = pg_server
    host = proc.host
    port = proc.port
    user = proc.user
    password = proc.password or ""
    template_dbname = proc.template_dbname
    test_dbname = f"dev_{uuid.uuid4().hex[:12]}"
    janitor = DatabaseJanitor(
        user=user,
        host=host,
        port=port,
        dbname=test_dbname,
        template_dbname=template_dbname,
        version=proc.version,
        password=password or None,
    )
    janitor.init()
    _set_dev_config(
        monkeypatch,
        host=host,
        port=str(port),
        db_name=test_dbname,
        username=user,
        password=password,
    )
    url = f"postgresql+asyncpg://{user}:{password}@{host}:{port}/{test_dbname}"
    eng = create_async_engine(url)
    await _seed_dev_user(eng)
    yield eng
    await eng.dispose()
    janitor.drop()
    await dispose_engine_factory()


@pytest_asyncio.fixture
async def dev_app(dev_engine, monkeypatch: pytest.MonkeyPatch):
    # DB + dev-IdP config was set by dev_engine; just clear the config cache
    # so create_app() rebuilds AppConfig from the env vars.
    get_config.cache_clear()
    factory = async_sessionmaker(dev_engine, expire_on_commit=False)

    async def _override_get_session() -> AsyncGenerator[AsyncSession, None]:
        async with factory() as s:
            yield s

    application = create_app()
    application.dependency_overrides[_app_get_session] = _override_get_session
    yield application
    application.dependency_overrides.clear()
    await dispose_engine_factory()


@pytest_asyncio.fixture
async def dev_client(dev_app) -> AsyncGenerator[AsyncClient, None]:
    transport = ASGITransport(app=dev_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


def _basic_auth(username: str, password: str) -> str:
    raw = f"{username}:{password}".encode()
    return "Basic " + base64.b64encode(raw).decode()


def _expected_callback() -> str:
    return f"{get_config().base_url.rstrip('/')}/auth/callback"


class TestDevLogin:
    """POST /auth/dev/login — username/password login that sets a session cookie."""

    async def test_login_sets_session_cookie(self, dev_client: AsyncClient) -> None:
        resp = await dev_client.post(
            "/auth/dev/login",
            json={"username": _DEV_USER_USERNAME, "password": _DEV_USER_PASSWORD},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["username"] == _DEV_USER_USERNAME
        assert body["user_id"] == "11111111-1111-1111-1111-111111111111"
        cookie_name = get_config().auth_cookie_name
        assert cookie_name in resp.cookies
        assert resp.cookies[cookie_name]

    async def test_login_cookie_authenticates_subsequent_request(
        self, dev_client: AsyncClient
    ) -> None:
        # /auth-clients requires a logged-in principal. Anonymous (no cookie)
        # is rejected as 403 by depends_permissions (no roles => deny). A valid
        # session cookie is accepted by depends_access_token (no 401) and also
        # 403s on the permission guard — but a *present-but-invalid* cookie is
        # 401. So we assert the authenticated request is not 401, proving the
        # cookie was recognized as a valid credential.
        anon = await dev_client.get("/auth-clients")
        assert anon.status_code == 403
        resp = await dev_client.post(
            "/auth/dev/login",
            json={"username": _DEV_USER_USERNAME, "password": _DEV_USER_PASSWORD},
        )
        assert resp.status_code == 200, resp.text
        authed = await dev_client.get("/auth-clients")
        assert authed.status_code != 401
        # A garbage cookie in the same name must produce 401 (sanity check that
        # the != 401 above is meaningful, not a route that never 401s).
        dev_client.cookies[get_config().auth_cookie_name] = "not-a-real-cookie"
        bad = await dev_client.get("/auth-clients")
        assert bad.status_code == 401

    async def test_login_rejects_bad_password(self, dev_client: AsyncClient) -> None:
        resp = await dev_client.post(
            "/auth/dev/login",
            json={"username": _DEV_USER_USERNAME, "password": "wrong"},
        )
        assert resp.status_code == 401
        cookie_name = get_config().auth_cookie_name
        assert cookie_name not in resp.cookies

    async def test_login_rejects_unknown_user(self, dev_client: AsyncClient) -> None:
        resp = await dev_client.post(
            "/auth/dev/login",
            json={"username": "nope", "password": _DEV_USER_PASSWORD},
        )
        assert resp.status_code == 401

    async def test_login_rejects_missing_fields(self, dev_client: AsyncClient) -> None:
        resp = await dev_client.post("/auth/dev/login", json={"username": _DEV_USER_USERNAME})
        assert resp.status_code == 422

    async def test_login_cookie_is_federated_shape(
        self, dev_client: AsyncClient, dev_engine, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from openhands.ev2.encryption.encryption_service import get_encryption_service

        _set_dev_config(monkeypatch)
        resp = await dev_client.post(
            "/auth/dev/login",
            json={"username": _DEV_USER_USERNAME, "password": _DEV_USER_PASSWORD},
        )
        assert resp.status_code == 200, resp.text
        enc = get_encryption_service()
        cookie = resp.cookies[get_config().auth_cookie_name]
        payload = enc.decrypt_jwe_token(cookie)
        # Same claims as the callback's cookie: sub, ttyp=cookie, aid, axp.
        assert payload["sub"] == "11111111-1111-1111-1111-111111111111"
        assert payload["ttyp"] == "cookie"
        assert "aid" in payload
        assert "axp" in payload
        # A persisted IdP access-token row must back the cookie.
        from sqlalchemy import select

        from openhands.ev2.auth.auth_models import IdpAccessToken, IdpRefreshToken
        from openhands.ev2.db import Base  # noqa: F401

        factory = async_sessionmaker(dev_engine, expire_on_commit=False)
        async with factory() as s:
            refresh = (await s.execute(select(IdpRefreshToken))).scalars().all()
            access = (await s.execute(select(IdpAccessToken))).scalars().all()
            assert len(refresh) == 1
            assert len(access) == 1
            assert str(access[0].id) == payload["aid"]


class TestDevAuthorize:
    async def test_authorize_returns_401_without_credentials(self, dev_client: AsyncClient) -> None:
        resp = await dev_client.get(
            "/auth/dev/authorize",
            params={
                "response_type": "code",
                "client_id": "ohe",
                "redirect_uri": _expected_callback(),
            },
            follow_redirects=False,
        )
        assert resp.status_code == 401
        assert resp.headers["www-authenticate"].lower().startswith("basic")

    async def test_authorize_returns_401_with_bad_password(self, dev_client: AsyncClient) -> None:
        resp = await dev_client.get(
            "/auth/dev/authorize",
            params={
                "response_type": "code",
                "client_id": "ohe",
                "redirect_uri": _expected_callback(),
            },
            headers={"Authorization": _basic_auth(_DEV_USER_USERNAME, "wrong")},
            follow_redirects=False,
        )
        assert resp.status_code == 401

    async def test_authorize_returns_401_for_unknown_user(self, dev_client: AsyncClient) -> None:
        resp = await dev_client.get(
            "/auth/dev/authorize",
            params={
                "response_type": "code",
                "client_id": "ohe",
                "redirect_uri": _expected_callback(),
            },
            headers={"Authorization": _basic_auth("nope", _DEV_USER_PASSWORD)},
            follow_redirects=False,
        )
        assert resp.status_code == 401

    async def test_authorize_rejects_unknown_client(self, dev_client: AsyncClient) -> None:
        resp = await dev_client.get(
            "/auth/dev/authorize",
            params={
                "response_type": "code",
                "client_id": "not-ohe",
                "redirect_uri": _expected_callback(),
            },
            headers={"Authorization": _basic_auth(_DEV_USER_USERNAME, _DEV_USER_PASSWORD)},
            follow_redirects=False,
        )
        assert resp.status_code == 401

    async def test_authorize_rejects_bad_redirect_uri(self, dev_client: AsyncClient) -> None:
        resp = await dev_client.get(
            "/auth/dev/authorize",
            params={
                "response_type": "code",
                "client_id": "ohe",
                "redirect_uri": "https://evil.example.com/cb",
            },
            headers={"Authorization": _basic_auth(_DEV_USER_USERNAME, _DEV_USER_PASSWORD)},
            follow_redirects=False,
        )
        assert resp.status_code == 400

    async def test_authorize_redirects_with_code(self, dev_client: AsyncClient) -> None:
        resp = await dev_client.get(
            "/auth/dev/authorize",
            params={
                "response_type": "code",
                "client_id": "ohe",
                "redirect_uri": _expected_callback(),
                "state": "client-state",
            },
            headers={"Authorization": _basic_auth(_DEV_USER_USERNAME, _DEV_USER_PASSWORD)},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        location = resp.headers["location"]
        assert location.startswith(f"{_expected_callback()}/?")
        qs = parse_qs(urlparse(location).query)
        assert "code" in qs
        assert qs["state"] == ["client-state"]


class TestDevToken:
    async def _get_code(self, client: AsyncClient) -> str:
        resp = await client.get(
            "/auth/dev/authorize",
            params={
                "response_type": "code",
                "client_id": "ohe",
                "redirect_uri": _expected_callback(),
            },
            headers={"Authorization": _basic_auth(_DEV_USER_USERNAME, _DEV_USER_PASSWORD)},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        return parse_qs(urlparse(resp.headers["location"]).query)["code"][0]

    async def test_token_exchange_happy_path(self, dev_client: AsyncClient) -> None:
        code = await self._get_code(dev_client)
        resp = await dev_client.post(
            "/auth/dev/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": _expected_callback(),
                "client_id": "ohe",
                "client_secret": "changeme",
            },
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["access_token"]
        assert body["refresh_token"]
        assert body["token_type"] == "Bearer"
        assert body["expires_in"] > 0
        assert body["refresh_expires_in"] > 0
        # id_token carries sub (local user id) + email for JIT provisioning.
        id_token = body["id_token"]
        payload_b64 = id_token.split(".")[1]
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        claims = json.loads(base64.urlsafe_b64decode(padded))
        assert claims["sub"] == "11111111-1111-1111-1111-111111111111"
        assert claims["email"] == "dev@example.com"

    async def test_token_rejects_bad_client_secret(self, dev_client: AsyncClient) -> None:
        code = await self._get_code(dev_client)
        resp = await dev_client.post(
            "/auth/dev/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": _expected_callback(),
                "client_id": "ohe",
                "client_secret": "wrong",
            },
        )
        assert resp.status_code == 401

    async def test_token_rejects_redirect_uri_mismatch(self, dev_client: AsyncClient) -> None:
        code = await self._get_code(dev_client)
        resp = await dev_client.post(
            "/auth/dev/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://evil.example.com/cb",
                "client_id": "ohe",
                "client_secret": "changeme",
            },
        )
        assert resp.status_code == 400

    async def test_token_rejects_garbage_code(self, dev_client: AsyncClient) -> None:
        resp = await dev_client.post(
            "/auth/dev/token",
            data={
                "grant_type": "authorization_code",
                "code": "not-a-real-code",
                "redirect_uri": _expected_callback(),
                "client_id": "ohe",
                "client_secret": "changeme",
            },
        )
        assert resp.status_code == 400

    async def test_token_rejects_unsupported_grant(self, dev_client: AsyncClient) -> None:
        resp = await dev_client.post(
            "/auth/dev/token",
            data={
                "grant_type": "password",
                "client_id": "ohe",
                "client_secret": "changeme",
            },
        )
        assert resp.status_code == 400


class TestDevRefresh:
    async def _get_tokens(self, client: AsyncClient) -> dict[str, str]:
        resp = await client.get(
            "/auth/dev/authorize",
            params={
                "response_type": "code",
                "client_id": "ohe",
                "redirect_uri": _expected_callback(),
            },
            headers={"Authorization": _basic_auth(_DEV_USER_USERNAME, _DEV_USER_PASSWORD)},
            follow_redirects=False,
        )
        code = parse_qs(urlparse(resp.headers["location"]).query)["code"][0]
        tok = await client.post(
            "/auth/dev/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": _expected_callback(),
                "client_id": "ohe",
                "client_secret": "changeme",
            },
        )
        assert tok.status_code == 200, tok.text
        return tok.json()

    async def test_refresh_at_token_endpoint(self, dev_client: AsyncClient) -> None:
        tokens = await self._get_tokens(dev_client)
        resp = await dev_client.post(
            "/auth/dev/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": tokens["refresh_token"],
                "client_id": "ohe",
                "client_secret": "changeme",
            },
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["access_token"]
        assert body["refresh_token"]
        assert body["id_token"]

    async def test_refresh_at_refresh_endpoint(self, dev_client: AsyncClient) -> None:
        tokens = await self._get_tokens(dev_client)
        resp = await dev_client.post(
            "/auth/dev/refresh",
            data={
                "refresh_token": tokens["refresh_token"],
                "client_id": "ohe",
                "client_secret": "changeme",
            },
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["access_token"]
        assert body["refresh_token"]

    async def test_refresh_rejects_bad_client(self, dev_client: AsyncClient) -> None:
        tokens = await self._get_tokens(dev_client)
        resp = await dev_client.post(
            "/auth/dev/refresh",
            data={
                "refresh_token": tokens["refresh_token"],
                "client_id": "ohe",
                "client_secret": "wrong",
            },
        )
        assert resp.status_code == 401

    async def test_refresh_rejects_garbage_token(self, dev_client: AsyncClient) -> None:
        resp = await dev_client.post(
            "/auth/dev/refresh",
            data={
                "refresh_token": "not-a-real-refresh-token",
                "client_id": "ohe",
                "client_secret": "changeme",
            },
        )
        assert resp.status_code == 400


class TestDevIdpServicePkce:
    """Unit tests for PKCE verification in the DevIdpService."""

    async def test_pkce_s256_verifier_accepted(
        self, dev_engine, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import hashlib

        from openhands.ev2.encryption.encryption_service import get_encryption_service

        _set_dev_config(monkeypatch)
        factory = async_sessionmaker(dev_engine, expire_on_commit=False)
        verifier = "v" * 64
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        async with factory() as session:
            service = DevIdpService(session)
            enc = get_encryption_service()
            code = enc.create_jwe_token(
                {
                    "sub": "11111111-1111-1111-1111-111111111111",
                    "ttyp": "dev_authorization_code",
                    "jti": str(uuid.uuid4()),
                    "email": "dev@example.com",
                    "cid": "ohe",
                    "ruri": _expected_callback(),
                    "cc": challenge,
                    "ccm": "S256",
                },
                expires_in=__import__("datetime").timedelta(minutes=5),
            )
            resp = await service.exchange_code(
                code=code,
                redirect_uri=_expected_callback(),
                client_id="ohe",
                client_secret="changeme",
                code_verifier=verifier,
            )
            assert resp["access_token"]

    async def test_pkce_wrong_verifier_rejected(
        self, dev_engine, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import hashlib

        from openhands.ev2.encryption.encryption_service import get_encryption_service

        _set_dev_config(monkeypatch)
        factory = async_sessionmaker(dev_engine, expire_on_commit=False)
        verifier = "v" * 64
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        async with factory() as session:
            service = DevIdpService(session)
            enc = get_encryption_service()
            code = enc.create_jwe_token(
                {
                    "sub": "11111111-1111-1111-1111-111111111111",
                    "ttyp": "dev_authorization_code",
                    "jti": str(uuid.uuid4()),
                    "email": "dev@example.com",
                    "cid": "ohe",
                    "ruri": _expected_callback(),
                    "cc": challenge,
                    "ccm": "S256",
                },
                expires_in=__import__("datetime").timedelta(minutes=5),
            )
            from openhands.ev2.auth.dev_router import InvalidGrantError

            with pytest.raises(InvalidGrantError):
                await service.exchange_code(
                    code=code,
                    redirect_uri=_expected_callback(),
                    client_id="ohe",
                    client_secret="changeme",
                    code_verifier="wrong-verifier",
                )


class TestAuthServiceDevUrlResolution:
    """The AuthService resolves a relative idp.url against base_url for httpx."""

    async def test_build_authorize_redirect_uses_absolute_dev_url(
        self, dev_engine, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from openhands.ev2.auth.auth_models import OAuthClientRedirectUri
        from openhands.ev2.auth.auth_service import AuthService

        _set_dev_config(monkeypatch)
        factory = async_sessionmaker(dev_engine, expire_on_commit=False)
        async with factory() as session:
            client = OAuthClient(
                client_id="ohe",
                client_secret="x",
                name="dev",
                enabled=True,
            )
            session.add(client)
            await session.flush()
            session.add(
                OAuthClientRedirectUri(client_id=client.id, uri="https://app.example.com/cb")
            )
            await session.flush()
            service = AuthService(session)
            url = await service.build_authorize_redirect(
                client_id="ohe",
                redirect_uri="https://app.example.com/cb",
                state=None,
                scope=None,
                code_challenge=None,
                code_challenge_method=None,
                callback_url=f"{get_config().base_url}/auth/callback",
                response_type="code",
            )
            await service.aclose()
        # The relative /auth/dev is resolved against base_url (http://test).
        assert url.startswith("http://test/auth/dev/authorize?")

    async def test_idp_base_resolves_relative(
        self, dev_engine, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from openhands.ev2.auth.auth_service import AuthService

        _set_dev_config(monkeypatch)
        factory = async_sessionmaker(dev_engine, expire_on_commit=False)
        async with factory() as session:
            service = AuthService(session)
            assert service._idp_base() == "http://test/auth/dev"
            await service.aclose()

    async def test_idp_base_passes_absolute_through(
        self, dev_engine, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from openhands.ev2.auth.auth_service import AuthService

        _set_dev_config(monkeypatch)
        monkeypatch.setenv("OHE_IDP_URL", "https://real-idp.example.com")
        get_config.cache_clear()
        factory = async_sessionmaker(dev_engine, expire_on_commit=False)
        async with factory() as session:
            service = AuthService(session)
            assert service._idp_base() == "https://real-idp.example.com"
            await service.aclose()


class TestDevIdpServiceHelpers:
    """Unit tests for DevIdpService internal helpers (no HTTP needed)."""

    @pytest_asyncio.fixture
    async def service(self, dev_engine) -> DevIdpService:
        from openhands.ev2.encryption.encryption_service import get_encryption_service

        enc = get_encryption_service()
        return DevIdpService(enc)

    async def test_decrypt_garbage_raises_invalid_grant(self, service: DevIdpService) -> None:
        from openhands.ev2.auth.dev_router import InvalidGrantError

        with pytest.raises(InvalidGrantError, match="decryption"):
            service._decrypt("not-a-valid-token")

    async def test_user_id_missing_subject_raises(self, service: DevIdpService) -> None:
        from openhands.ev2.auth.dev_router import InvalidGrantError

        with pytest.raises(InvalidGrantError, match="subject"):
            service._user_id({})

    async def test_user_id_invalid_uuid_raises(self, service: DevIdpService) -> None:
        from openhands.ev2.auth.dev_router import InvalidGrantError

        with pytest.raises(InvalidGrantError, match="subject"):
            service._user_id({"sub": "not-a-uuid"})

    async def test_email_missing_raises(self, service: DevIdpService) -> None:
        from openhands.ev2.auth.dev_router import InvalidGrantError

        with pytest.raises(InvalidGrantError, match="email"):
            service._email({})

    async def test_email_empty_string_raises(self, service: DevIdpService) -> None:
        from openhands.ev2.auth.dev_router import InvalidGrantError

        with pytest.raises(InvalidGrantError, match="email"):
            service._email({"email": ""})


class TestHandleTokenErrorPaths:
    """Tests for _handle_token error branches via the /auth/dev/token endpoint."""

    async def test_token_missing_code_raises_400(self, dev_client: AsyncClient) -> None:
        resp = await dev_client.post(
            "/auth/dev/token",
            data={
                "grant_type": "authorization_code",
                "redirect_uri": "http://test/cb",
                "client_id": "ohe",
                "client_secret": "changeme",
            },
        )
        assert resp.status_code == 400

    async def test_token_missing_refresh_token_raises_400(self, dev_client: AsyncClient) -> None:
        resp = await dev_client.post(
            "/auth/dev/token",
            data={
                "grant_type": "refresh_token",
                "client_id": "ohe",
                "client_secret": "changeme",
            },
        )
        assert resp.status_code == 400

    async def test_refresh_endpoint_with_wrong_grant_type_normalizes(
        self, dev_client: AsyncClient
    ) -> None:
        """The refresh endpoint forces grant_type to 'refresh_token' even if wrong."""
        resp = await dev_client.post(
            "/auth/dev/refresh",
            data={
                "grant_type": "authorization_code",
                "refresh_token": "garbage",
                "client_id": "ohe",
                "client_secret": "changeme",
            },
        )
        # Should be 400 (garbage token) not 422 or other error
        assert resp.status_code == 400
