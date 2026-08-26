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

from ohev.app import create_app
from ohev.config import get_config
from ohev.db import Base, reset_engine_factory
from ohev.permission.permission_models import Permission  # noqa: F401
from ohev.user.user_models import User  # noqa: F401

# Detect a running postgres socket dir set up by the dev environment; fall back
# to the default localhost DSN used by docker-compose.
_PGSOCK = os.environ.get("OHEV_PGSOCK", "")
_TEST_DB_URL = (
    f"postgresql+asyncpg://ohev@/ohev?host={_PGSOCK}"
    if _PGSOCK
    else os.environ.get("OHEV_DATABASE_URL", "postgresql+asyncpg://ohev:ohev@localhost:5432/ohev")
)

# Default test principal — sent as X-User-Id so the permission flow is exercised.
_TEST_USER_ID = uuid.UUID("12345678-1234-5678-1234-456789abcdef")


def _set_test_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """Point AppConfig at the test database and reset cached engine/factory."""
    get_config.cache_clear()
    reset_engine_factory()
    from ohev.permission.permission_service import reset_base_permissions_cache

    reset_base_permissions_cache()
    monkeypatch.setenv("OHEV_ENCRYPTION_KEY_VALUE", "test-secret-at-least-32-bytes-long!!")
    monkeypatch.setenv("OHEV_DATABASE_URL", _TEST_DB_URL)
    # Baseline grants that allow all CRUD-L on user and permission resources so
    # existing service/route tests pass without per-user DB permissions. Tests
    # that verify denial override this env var locally.
    monkeypatch.setenv("OHEV_BASE_PERMISSIONS_0", "all:user")
    monkeypatch.setenv("OHEV_BASE_PERMISSIONS_1", "all:permission")


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
    reset_engine_factory()


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
    engine so route tests are hermetic.
    """
    _set_test_config(monkeypatch)
    from ohev.db import get_session as _app_get_session

    factory = async_sessionmaker(engine, expire_on_commit=False)

    async def _override_get_session() -> AsyncGenerator[AsyncSession, None]:
        async with factory() as s:
            yield s

    application = create_app()
    application.dependency_overrides[_app_get_session] = _override_get_session
    yield application
    application.dependency_overrides.clear()
    reset_engine_factory()


@pytest_asyncio.fixture
async def client(app) -> AsyncGenerator[AsyncClient, None]:
    """An async HTTP client backed by the test app.

    Sends a default X-User-Id header so every request is authenticated as the
    test principal, satisfying the permission dependencies' auth requirement.
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        headers={"X-User-Id": str(_TEST_USER_ID)},
    ) as ac:
        yield ac


@pytest.fixture
def user_id() -> uuid.UUID:
    """A deterministic user id for permission fixtures."""
    return _TEST_USER_ID
