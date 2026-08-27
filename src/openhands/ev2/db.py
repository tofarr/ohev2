"""Shared SQLAlchemy declarative base and async session infrastructure.

All feature models import `Base` from here so Alembic autogenerate sees a single
`MetaData` object. The session/engine factories are async-first per AGENTS.md §1.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import Annotated, Any

from fastapi import Depends
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, MappedAsDataclass

from openhands.ev2.config import get_config


class Base(MappedAsDataclass, DeclarativeBase):
    """Declarative base shared by all ORM models.

    Uses `MappedAsDataclass` so model instances are dataclasses with equality,
    useful for assertions in tests.
    """


def create_engine(url: str, **kwargs: Any) -> AsyncEngine:
    """Create an async engine for the given database URL."""
    return create_async_engine(url, **kwargs)


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Create a session factory bound to an engine."""
    return async_sessionmaker(engine, expire_on_commit=False)


# Application-scoped engine + factory, lazily initialized from AppConfig.
_engine: AsyncEngine | None = None
_factory: async_sessionmaker[AsyncSession] | None = None


def get_engine() -> AsyncEngine:
    """Get the application-scoped async engine, creating it on first use."""
    global _engine
    if _engine is None:
        _engine = create_engine(get_config().database_url)
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Get the application-scoped session factory, creating it on first use."""
    global _factory
    if _factory is None:
        _factory = create_session_factory(get_engine())
    return _factory


def reset_engine_factory() -> None:
    """Reset the cached engine/factory (used by tests after config changes)."""
    global _engine, _factory
    _engine = None
    _factory = None


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency: yield a request-scoped session."""
    factory = get_session_factory()
    async with factory() as session:
        yield session


# Shared request-scoped session dependency. Lives here (not in a feature
# module) so routers, services, and the auth dependency all import it from one
# place rather than each feature redeclaring it.
SessionDep = Annotated[AsyncSession, Depends(get_session)]
