"""Shared pytest fixtures.

Uses an embedded PostgreSQL server (pytest-postgresql) so unit tests are hermetic.
Each test function gets a fresh database created from the live migration, and a
transactional session that rolls back after the test.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncGenerator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from openhands.ev2.app import create_app
from openhands.ev2.auth.auth_models import (  # noqa: F401
    ApiKey,
    IdpRefreshToken,
    OAuthClient,
    OAuthClientRedirectUri,
)
from openhands.ev2.config import get_config
from openhands.ev2.cors.cors_models import AllowedOrigin  # noqa: F401
from openhands.ev2.db import Base, reset_engine_factory
from openhands.ev2.feature_flag.feature_flag_models import (  # noqa: F401
    FeatureFlag,
    FeatureFlagRole,
)
from openhands.ev2.llm.llm_models import StoredLLM, StoredProviderConnection  # noqa: F401
from openhands.ev2.role.role_models import ROLE_ENTITY_COLUMNS, Role, UserRole
from openhands.ev2.security.security_models import Permitted
from openhands.ev2.user.user_models import User  # noqa: F401

# Detect a running postgres socket dir set up by the dev environment; fall back
# to the default localhost DSN used by docker-compose.
_PGSOCK = os.environ.get("OHE_PGSOCK", "")
_TEST_DB_URL = (
    f"postgresql+asyncpg://ohev@/ohev?host={_PGSOCK}"
    if _PGSOCK
    else "postgresql+asyncpg://ohev:ohev@localhost:5432/ohev"
)

# Default test principal — authenticated via a JWE cookie token minted in the
# client fixture (the same mechanism the login endpoint uses). The user is
# created in the DB during the engine fixture so authenticate() can resolve it.
_TEST_USER_ID = uuid.UUID("12345678-1234-5678-1234-456789abcdef")
_TEST_USERNAME = "test-principal"


def _set_test_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """Point AppConfig at the test database and reset cached engine/factory."""
    get_config.cache_clear()
    reset_engine_factory()
    from openhands.ev2.cors.cors_service import reset_cors_cache

    reset_cors_cache()
    monkeypatch.setenv("OHE_ENCRYPTION_KEY_VALUE", "test-secret-at-least-32-bytes-long!!")
    # Point the structured DbConfig at the test database (TCP localhost).
    monkeypatch.setenv("OHE_DB_CONFIG_HOST", "localhost")
    monkeypatch.setenv("OHE_DB_CONFIG_PORT", "5432")
    monkeypatch.setenv("OHE_DB_CONFIG_DB_NAME", "ohev")
    monkeypatch.setenv("OHE_DB_CONFIG_USERNAME", "ohev")
    monkeypatch.setenv("OHE_DB_CONFIG_PASSWORD", "ohev")
    # Federated OAuth (auth) — required config fields. Tests that exercise the
    # real IdP HTTP flow override the URL / mock httpx.
    monkeypatch.setenv("OHE_IDP_URL", "https://idp.example.com")
    monkeypatch.setenv("OHE_IDP_CLIENT_ID", "test-client")
    monkeypatch.setenv("OHE_IDP_CLIENT_SECRET", "test-secret")
    # Public base URL of the service; the callback URL handed to the IdP is
    # derived from this (config-driven, not request.base_url).
    monkeypatch.setenv("OHE_BASE_URL", "http://test")
    # Keep the background cleanup loop out of the test process.
    monkeypatch.setenv("OHE_CLEANUP_INTERVAL", "0")


# Per-entity ``Permission`` columns the seeded test admin role grants
# unrestricted access to. ``ROLE_ENTITY_COLUMNS`` (imported above) is the
# canonical list on the model, so the seeded admin role grants access to every
# resource.


async def _seed_test_admin_role(session: AsyncSession, user_id: uuid.UUID) -> None:
    """Assign the test principal an admin role that permits all actions.

    The role's per-entity ``Permission`` columns grant :class:`Permitted`
    (unrestricted access) for every shipped resource type, providing the
    baseline access route tests need under the role-based authorization
    dependency. Idempotent: re-running on an already-seeded role is a no-op.
    """
    from sqlalchemy import select

    role = (
        await session.execute(select(Role).where(Role.name == "test-admin"))
    ).scalar_one_or_none()
    if role is None:
        role = Role(
            name="test-admin",
            **{col: Permitted() for col in ROLE_ENTITY_COLUMNS},
        )
        session.add(role)
        await session.flush()
    existing = (
        await session.execute(
            select(UserRole).where(UserRole.role_id == role.id, UserRole.user_id == user_id)
        )
    ).scalar_one_or_none()
    if existing is None:
        session.add(UserRole(role_id=role.id, user_id=user_id))


@pytest_asyncio.fixture
async def engine(monkeypatch: pytest.MonkeyPatch):
    """A per-test async engine bound to the test database.

    The schema is created fresh from the model metadata (no alembic run needed
    in-process) and dropped after the test.
    """
    _set_test_config(monkeypatch)
    eng = create_async_engine(_TEST_DB_URL)
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await eng.dispose()
    from openhands.ev2.db import dispose_engine_factory

    await dispose_engine_factory()


@pytest_asyncio.fixture
async def session(engine) -> AsyncGenerator[AsyncSession, None]:
    """A transactional session that rolls back after each test."""
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as s:
        yield s
        await s.rollback()


@pytest_asyncio.fixture
async def app(engine, monkeypatch: pytest.MonkeyPatch):
    """A FastAPI app whose DB dependency uses the test engine.

    Overrides the `get_session` dependency to yield sessions from the test
    engine so route tests are hermetic. Also seeds the default test principal
    user so the auth dependency's DB-backed `authenticate` can resolve tokens
    minted for it.
    """
    _set_test_config(monkeypatch)
    from sqlalchemy import text

    from openhands.ev2.db import dispose_engine_factory
    from openhands.ev2.db import get_session as _app_get_session

    factory = async_sessionmaker(engine, expire_on_commit=False)
    # Seed the test principal (User.id is init=False, so insert via SQL).
    async with factory() as s:
        await s.execute(
            text(
                "INSERT INTO users (id, email, username, enabled) "
                "VALUES (:id, :email, :username, true) "
                "ON CONFLICT (id) DO NOTHING"
            ),
            {"id": _TEST_USER_ID, "email": "test@example.com", "username": _TEST_USERNAME},
        )
        await _seed_test_admin_role(s, _TEST_USER_ID)
        await s.commit()

    async def _override_get_session() -> AsyncGenerator[AsyncSession, None]:
        async with factory() as s:
            yield s

    application = create_app()
    application.dependency_overrides[_app_get_session] = _override_get_session
    yield application
    application.dependency_overrides.clear()
    # The CORS middleware reads origins via get_session_factory(), which builds
    # a separate app-scoped engine (not the overridden test dependency). Dispose
    # it so no asyncpg connections leak across tests.
    await dispose_engine_factory()


@pytest_asyncio.fixture
async def client(app, monkeypatch: pytest.MonkeyPatch) -> AsyncGenerator[AsyncClient, None]:
    """An async HTTP client authenticated as the test principal.

    Mints a JWE cookie token for the seeded test user and sends it via the
    X-API-Key header (the highest-priority auth source) so permission
    dependencies see a real principal.
    """
    from openhands.ev2.util.auth_token import create_auth_token

    get_config.cache_clear()
    token = create_auth_token(_TEST_USER_ID)
    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        headers={"X-API-Key": token},
    ) as ac:
        yield ac


@pytest.fixture
def user_id() -> uuid.UUID:
    """A deterministic user id for permission fixtures."""
    return _TEST_USER_ID
