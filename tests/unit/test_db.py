"""Tests for the DB session infrastructure in openhands.ev2.db."""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from openhands.ev2.config import get_config
from openhands.ev2.db import (
    Base,
    create_engine,
    create_session_factory,
    get_engine,
    get_session,
    get_session_factory,
    reset_engine_factory,
)


def _set_db_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Point the structured DbConfig at the test postgres for caching tests."""
    monkeypatch.setenv("OHE_DB_CONFIG_HOST", "localhost")
    monkeypatch.setenv("OHE_DB_CONFIG_PORT", "5432")
    monkeypatch.setenv("OHE_DB_CONFIG_DB_NAME", "ohev")
    monkeypatch.setenv("OHE_DB_CONFIG_USERNAME", "ohev")
    monkeypatch.setenv("OHE_DB_CONFIG_PASSWORD", "ohev")
    monkeypatch.setenv("OHE_ENCRYPTION_KEY_VALUE", "test-secret-at-least-32-bytes-long!!")
    monkeypatch.setenv("OHE_IDP_URL", "https://idp.example.com")
    monkeypatch.setenv("OHE_IDP_CLIENT_ID", "test-client")
    monkeypatch.setenv("OHE_IDP_CLIENT_SECRET", "test-secret")


class TestBase:
    def test_base_is_declarative(self) -> None:
        from sqlalchemy.orm import DeclarativeBase

        assert issubclass(Base, DeclarativeBase)

    def test_base_has_metadata(self) -> None:
        assert Base.metadata is not None


class TestFactoryFunctions:
    def test_create_engine_returns_async_engine(self, monkeypatch) -> None:
        eng = create_engine("sqlite+aiosqlite:///:memory:")
        assert isinstance(eng, AsyncEngine)

    def test_create_session_factory(self, monkeypatch) -> None:
        eng = create_engine("sqlite+aiosqlite:///:memory:")
        factory = create_session_factory(eng)
        assert isinstance(factory, async_sessionmaker)

    def test_get_engine_caches(self, monkeypatch) -> None:
        reset_engine_factory()
        get_config.cache_clear()
        _set_db_env(monkeypatch)
        eng1 = get_engine()
        eng2 = get_engine()
        assert eng1 is eng2
        reset_engine_factory()
        get_config.cache_clear()

    def test_get_session_factory_caches(self, monkeypatch) -> None:
        reset_engine_factory()
        get_config.cache_clear()
        _set_db_env(monkeypatch)
        f1 = get_session_factory()
        f2 = get_session_factory()
        assert f1 is f2
        reset_engine_factory()
        get_config.cache_clear()

    def test_reset_engine_factory_clears_cache(self, monkeypatch) -> None:
        reset_engine_factory()
        get_config.cache_clear()
        _set_db_env(monkeypatch)
        eng1 = get_engine()
        reset_engine_factory()
        eng2 = get_engine()
        assert eng1 is not eng2
        reset_engine_factory()
        get_config.cache_clear()


class TestGetSessionDependency:
    async def test_get_session_yields_session(self, monkeypatch) -> None:
        reset_engine_factory()
        get_config.cache_clear()
        _set_db_env(monkeypatch)
        gen = get_session()
        session = await gen.__anext__()
        assert isinstance(session, AsyncSession)
        with pytest.raises(StopAsyncIteration):
            await gen.__anext__()
        reset_engine_factory()
        get_config.cache_clear()
