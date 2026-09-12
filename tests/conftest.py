"""Shared pytest fixtures.

Uses an embedded PostgreSQL server (pytest-postgresql) so unit tests are hermetic
and parallelizable. A single Postgres process is started per test session and a
single database is created per xdist worker (or per session when running without
xdist). The schema is built once into the worker database. Each test runs inside
a SAVEPOINT transaction that is rolled back after the test — no per-test
``CREATE DATABASE``/``DROP DATABASE``.

All DB access in a test (the ``session`` fixture, the ``app`` fixture's
dependency override, and the module-level ``get_session_factory()`` used by
middleware) goes through the same per-test connection, so committed savepoint
data is visible across sessions within a test, yet invisible to other tests.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncGenerator

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
from sqlalchemy.pool import NullPool

from openhands.ev2.app import create_app
from openhands.ev2.auth.auth_models import (  # noqa: F401
    ApiKey,
    IdpRefreshToken,
    OAuthClient,
    OAuthClientRedirectUri,
)
from openhands.ev2.config import get_config
from openhands.ev2.conversation.conversation_models import Conversation  # noqa: F401
from openhands.ev2.cors.cors_models import AllowedOrigin  # noqa: F401
from openhands.ev2.feature_flag.feature_flag_models import (  # noqa: F401
    FeatureFlag,
    FeatureFlagRoleAssignment,
    FeatureFlagUserAssignment,
)
from openhands.ev2.group.group_models import Group, GroupUser  # noqa: F401
from openhands.ev2.llm.llm_models import (  # noqa: F401
    LlmAggregatedUsage,
    LlmUsage,
    StoredLLM,
    StoredProviderConnection,
)
from openhands.ev2.mcp_server_config.mcp_server_config_models import (  # noqa: F401
    MCPServerConfig,
)
from openhands.ev2.mcp_server_config.mcp_usage_models import (  # noqa: F401
    McpAggregatedUsage,
    McpUsage,
)
from openhands.ev2.role.role_models import ROLE_ENTITY_COLUMNS, Role, UserRole
from openhands.ev2.sandbox.sandbox_config_models import SandboxConfig  # noqa: F401
from openhands.ev2.sandbox.sandbox_snapshot_models import SandboxSnapshot  # noqa: F401
from openhands.ev2.sandbox.sandbox_template_models import SandboxTemplate  # noqa: F401
from openhands.ev2.sandbox.sandbox_usage_models import SandboxUsage  # noqa: F401
from openhands.ev2.secret.sql_secrets_models import (  # noqa: F401
    SqlSecret,
)
from openhands.ev2.security.security_models import Permitted
from openhands.ev2.user.user_models import User  # noqa: F401

# Default test principal — authenticated via a JWE cookie token minted in the
# client fixture (the same mechanism the login endpoint uses). The user is
# created in the DB during the app fixture so authenticate() can resolve it.
_TEST_USER_ID = uuid.UUID("12345678-1234-5678-1234-456789abcdef")
_TEST_USERNAME = "test-principal"


def _build_schema(host: str, port: int, user: str, password: str, dbname: str) -> None:
    """Create the full ORM schema + DEFAULT partitions in a database.

    Runs on a throwaway event loop (``asyncio.run``) so it does not tie
    connections to any test's event loop. Called once per worker DB at session
    scope; tests then roll back.
    """
    # Importing the model modules registers every table on ``Base.metadata``.
    import openhands.ev2.auth.auth_models
    import openhands.ev2.conversation.conversation_models
    import openhands.ev2.cors.cors_models
    import openhands.ev2.feature_flag.feature_flag_models
    import openhands.ev2.group.group_models
    import openhands.ev2.llm.llm_models
    import openhands.ev2.mcp_server_config.mcp_server_config_models
    import openhands.ev2.mcp_server_config.mcp_usage_models
    import openhands.ev2.role.role_models
    import openhands.ev2.sandbox.sandbox_config_models
    import openhands.ev2.sandbox.sandbox_snapshot_models
    import openhands.ev2.sandbox.sandbox_template_models
    import openhands.ev2.sandbox.sandbox_usage_models
    import openhands.ev2.secret.sql_secrets_models
    import openhands.ev2.user.user_models  # noqa: F401
    from openhands.ev2.db import Base

    url = f"postgresql+asyncpg://{user}:{password}@{host}:{port}/{dbname}"

    async def _run() -> None:
        eng = create_async_engine(url, poolclass=NullPool)
        try:
            async with eng.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
                await conn.execute(
                    text(
                        "CREATE TABLE IF NOT EXISTS llm_usage_default "
                        "PARTITION OF llm_usage DEFAULT"
                    )
                )
                await conn.execute(
                    text(
                        "CREATE TABLE IF NOT EXISTS mcp_usage_default "
                        "PARTITION OF mcp_usage DEFAULT"
                    )
                )
                await conn.execute(
                    text(
                        "CREATE TABLE IF NOT EXISTS sandbox_usage_default "
                        "PARTITION OF sandbox_usage DEFAULT"
                    )
                )
        finally:
            await eng.dispose()

    asyncio.run(_run())


def _set_test_env(
    monkeypatch: pytest.MonkeyPatch,
    *,
    host: str | None = None,
    port: str | None = None,
    db_name: str | None = None,
    username: str | None = None,
    password: str | None = None,
) -> None:
    """Set test env vars for AppConfig.

    DB coordinates are optional: callers that already set them via
    the ``db_engine`` fixture (e.g. ``app``) omit them to keep prior values.
    Does NOT call reset_engine_factory — the per-test fixture manages
    db._engine/_factory directly.
    """
    get_config.cache_clear()
    from openhands.ev2.cors.cors_service import reset_cors_cache

    reset_cors_cache()
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
    # Federated OAuth (auth) — required config fields. Tests that exercise the
    # real IdP HTTP flow override the URL / mock httpx.
    monkeypatch.setenv("OHE_IDP_URL", "https://idp.example.com")
    monkeypatch.setenv("OHE_IDP_CLIENT_ID", "test-client")
    monkeypatch.setenv("OHE_IDP_CLIENT_SECRET", "test-secret")
    monkeypatch.setenv("OHE_BASE_URL", "http://test")
    monkeypatch.setenv("OHE_CLEANUP_INTERVAL", "0")
    monkeypatch.setenv("OHE_LLM_USAGE_PARTITION_INTERVAL", "0")
    monkeypatch.setenv("OHE_LLM_USAGE_AGGREGATE_INTERVAL", "0")
    monkeypatch.setenv("OHE_MCP_USAGE_PARTITION_INTERVAL", "0")
    monkeypatch.setenv("OHE_MCP_USAGE_AGGREGATE_INTERVAL", "0")


async def _seed_test_admin_role(session: AsyncSession, user_id: uuid.UUID) -> None:
    """Assign the test principal an admin role that permits all actions.

    Idempotent: re-running on an already-seeded role is a no-op.
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


def _worker_id(request: pytest.FixtureRequest) -> str:
    """Return the xdist worker id, or 'main' when xdist is not active."""
    try:
        return request.getfixturevalue("worker_id")
    except Exception:
        return "main"


@pytest.fixture(scope="session")
def pg_server(request: pytest.FixtureRequest) -> tuple[PostgreSQLExecutor, AsyncEngine]:
    """Start embedded PG, create one DB per worker, build schema, and return
    ``(proc, engine)``.

    The engine uses ``NullPool`` so connections are never shared across
    event loops — each ``connect()`` creates a fresh asyncpg connection on
    the caller's event loop, and ``close()`` returns it to the OS.
    """
    proc: PostgreSQLExecutor = request.getfixturevalue("postgresql_proc")
    host = proc.host
    port = proc.port
    user = proc.user
    password = proc.password or ""
    wid = _worker_id(request)
    dbname = f"testdb_{wid}"[:63]

    janitor = DatabaseJanitor(
        user=user,
        host=host,
        port=port,
        dbname=dbname,
        template_dbname=proc.template_dbname,
        version=proc.version,
        password=password or None,
    )
    janitor.init()
    _build_schema(host, port, user, password, dbname)

    url = f"postgresql+asyncpg://{user}:{password}@{host}:{port}/{dbname}"
    eng = create_async_engine(url, poolclass=NullPool)

    request.session.addfinalizer(lambda: janitor.drop())

    # Keep a reference so the engine is not GC'd (and its finalizer doesn't
    # warn) — the connection pool is empty (NullPool) so no async dispose is
    # needed.
    _session_engine_holder.engine = eng  # type: ignore[attr-defined]
    return proc, eng


class _EngineHolder:
    """Holds a reference to the session-scoped engine to prevent GC."""

    engine: AsyncEngine | None = None


_session_engine_holder = _EngineHolder()


@pytest_asyncio.fixture
async def engine(
    monkeypatch: pytest.MonkeyPatch,
    pg_server: tuple[PostgreSQLExecutor, AsyncEngine],
) -> AsyncGenerator[AsyncEngine, None]:
    """A per-test savepoint transaction wrapper around the shared engine.

    Begins an outer transaction on a fresh connection, yields the engine, then
    rolls back. Sessions created via the ``session`` fixture (and via
    ``get_session_factory()`` in production code paths like the CORS
    middleware) bind to this connection with ``join_transaction_mode=
    "create_savepoint"``, so ``session.commit()`` only releases a savepoint —
    data is visible within the test but rolled back after it.
    """
    from openhands.ev2 import db as db_module

    _proc, db_engine = pg_server
    host = db_engine.url.host
    port = str(db_engine.url.port)
    user = db_engine.url.username
    password = db_engine.url.password or ""
    db_name = db_engine.url.database
    _set_test_env(
        monkeypatch,
        host=host,
        port=port,
        db_name=db_name,
        username=user,
        password=password,
    )

    conn = await db_engine.connect()
    tx = await conn.begin()
    # Bind the module-level factory to this connection so ALL DB access
    # (session fixture, app dependency override, CORS middleware via
    # get_session_factory()) participates in the savepoint transaction.
    factory = async_sessionmaker(
        bind=conn,
        expire_on_commit=False,
        join_transaction_mode="create_savepoint",
    )
    old_engine = db_module._engine
    old_factory = db_module._factory
    db_module._engine = db_engine
    db_module._factory = factory

    yield db_engine

    db_module._factory = old_factory
    db_module._engine = old_engine
    await tx.rollback()
    await conn.close()


@pytest_asyncio.fixture
async def session(engine) -> AsyncGenerator[AsyncSession, None]:
    """A session that participates in the per-test savepoint transaction.

    ``commit()`` releases the savepoint (data visible within the test);
    the outer transaction is rolled back after the test.
    """
    from openhands.ev2.db import get_session_factory

    factory = get_session_factory()
    async with factory() as s:
        yield s
        await s.rollback()


@pytest_asyncio.fixture
async def app(engine, monkeypatch: pytest.MonkeyPatch):
    """A FastAPI app whose DB dependency uses the per-test savepoint transaction.

    Seeds the default test principal user so the auth dependency's DB-backed
    ``authenticate`` can resolve tokens minted for it.
    """
    _set_test_env(monkeypatch)

    from openhands.ev2.db import get_session as _app_get_session
    from openhands.ev2.db import get_session_factory

    factory = get_session_factory()
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
        # Mirror the production get_session lifecycle (db.py): commit on
        # success, rollback on exception. The commit matters for app-scoped
        # services (e.g. SqlSecretsService) that open their own savepoint
        # sessions on the shared test connection: a dependency session that
        # closes without committing would ROLLBACK TO its (earlier) savepoint
        # and undo work the service committed inside it.
        async with factory() as s:
            try:
                yield s
            except Exception:
                await s.rollback()
                raise
            else:
                await s.commit()

    application = create_app()
    application.dependency_overrides[_app_get_session] = _override_get_session
    # ASGITransport does not run the lifespan, so wire the app-scoped services
    # the lifespan would normally provide (see app.py). The default SQL-backed
    # secrets service runs against the per-test savepoint transaction via the
    # patched get_session_factory().
    from openhands.ev2.secret.sql_secrets_service import SqlSecretsService

    application.state.secrets_service = SqlSecretsService()
    yield application
    application.dependency_overrides.clear()


@pytest_asyncio.fixture
async def client(app, monkeypatch: pytest.MonkeyPatch) -> AsyncGenerator[AsyncClient, None]:
    """An async HTTP client authenticated as the test principal."""
    from openhands.ev2.util.auth_token import create_auth_token

    get_config.cache_clear()
    token = create_auth_token(_TEST_USER_ID)
    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        headers={"Authorization": f"Bearer {token}"},
    ) as ac:
        yield ac


@pytest.fixture
def user_id() -> uuid.UUID:
    """A deterministic user id for permission fixtures."""
    return _TEST_USER_ID
