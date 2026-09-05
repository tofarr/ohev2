"""Shared pytest fixtures.

Uses an embedded PostgreSQL server (pytest-postgresql) so unit tests are hermetic
and parallelizable. A single Postgres process is started per test session; the
schema is built once into a *template* database, and each test gets a fresh
database cloned from that template via ``CREATE DATABASE ... TEMPLATE`` (a fast
file-level copy — no per-test DDL). Sessions roll back after each test.
"""

from __future__ import annotations

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

from openhands.ev2.app import create_app
from openhands.ev2.auth.auth_models import (  # noqa: F401
    ApiKey,
    IdpRefreshToken,
    OAuthClient,
    OAuthClientRedirectUri,
)
from openhands.ev2.config import get_config
from openhands.ev2.cors.cors_models import AllowedOrigin  # noqa: F401
from openhands.ev2.db import reset_engine_factory
from openhands.ev2.feature_flag.feature_flag_models import (  # noqa: F401
    FeatureFlag,
    FeatureFlagRoleAssignment,
    FeatureFlagUserAssignment,
)
from openhands.ev2.llm.llm_models import (  # noqa: F401
    LlmAggregatedUsage,
    LlmUsage,
    StoredLLM,
    StoredProviderConnection,
)
from openhands.ev2.mcp_server_config.mcp_server_config_models import (  # noqa: F401
    MCPServerConfig,
    RoleMCPServerConfigPermission,
)
from openhands.ev2.mcp_server_config.mcp_usage_models import (  # noqa: F401
    McpAggregatedUsage,
    McpUsage,
)
from openhands.ev2.role.role_models import ROLE_ENTITY_COLUMNS, Role, UserRole
from openhands.ev2.secret.secret_models import (  # noqa: F401
    RoleSecretPermission,
    Secret,
    UserSecretPermission,
)
from openhands.ev2.security.security_models import Permitted
from openhands.ev2.user.user_models import User  # noqa: F401

# Default test principal — authenticated via a JWE cookie token minted in the
# client fixture (the same mechanism the login endpoint uses). The user is
# created in the DB during the engine fixture so authenticate() can resolve it.
_TEST_USER_ID = uuid.UUID("12345678-1234-5678-1234-456789abcdef")
_TEST_USERNAME = "test-principal"

# Embedded PostgreSQL process, started once per test session by the
# pytest-postgresql plugin's built-in ``postgresql_proc`` fixture. The plugin's
# ``_pg_exe`` helper resolves the real ``pg_ctl`` via ``pg_config --bindir``
# (PG 17 here), so no explicit executable is needed. The schema is built once
# into the plugin's template database (``<dbname>_tmpl``); every per-test
# database is then a cheap ``CREATE DATABASE ... TEMPLATE`` clone of it.


def _build_template_schema(host: str, port: int, user: str, password: str, dbname: str) -> None:
    """Create the full ORM schema + llm_usage DEFAULT partition in a database.

    Used to populate the session template once; cloned per test thereafter.
    """
    import asyncio

    # Importing the model modules registers every table on ``Base.metadata``.
    import openhands.ev2.auth.auth_models
    import openhands.ev2.cors.cors_models
    import openhands.ev2.feature_flag.feature_flag_models
    import openhands.ev2.llm.llm_models
    import openhands.ev2.mcp_server_config.mcp_server_config_models
    import openhands.ev2.mcp_server_config.mcp_usage_models
    import openhands.ev2.role.role_models
    import openhands.ev2.secret.secret_models
    import openhands.ev2.user.user_models  # noqa: F401
    from openhands.ev2.db import Base

    url = f"postgresql+asyncpg://{user}:{password}@{host}:{port}/{dbname}"

    async def _run() -> None:
        eng = create_async_engine(url)
        try:
            async with eng.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
                # llm_usage and mcp_usage are range-partitioned by created_at;
                # create_all emits only the parents. Add DEFAULT partitions so
                # test inserts land somewhere before dated partitions exist.
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
        finally:
            await eng.dispose()

    asyncio.run(_run())


@pytest.fixture(scope="session")
def pg_server(request: pytest.FixtureRequest) -> PostgreSQLExecutor:
    """Start the embedded PG once and build the schema template.

    Returns the underlying :class:`PostgreSQLExecutor` so per-test fixtures can
    read ``host``/``port``/``user``/``password``/``template_dbname``/``dbname``
    and the server ``version`` (needed by :class:`DatabaseJanitor`).
    """
    proc: PostgreSQLExecutor = request.getfixturevalue("postgresql_proc")
    _build_template_schema(
        proc.host, proc.port, proc.user, proc.password or "", proc.template_dbname
    )
    return proc


def _set_test_config(
    monkeypatch: pytest.MonkeyPatch,
    *,
    host: str | None = None,
    port: str | None = None,
    db_name: str | None = None,
    username: str | None = None,
    password: str | None = None,
) -> None:
    """Point AppConfig at a test database and reset cached engine/factory.

    The DB coordinates are optional: callers that have already set them via
    the ``engine`` fixture (e.g. ``app``) omit them to keep the prior values.
    """
    get_config.cache_clear()
    reset_engine_factory()
    from openhands.ev2.cors.cors_service import reset_cors_cache

    reset_cors_cache()
    monkeypatch.setenv("OHE_ENCRYPTION_KEY_VALUE", "test-secret-at-least-32-bytes-long!!")
    # Point the structured DbConfig at the embedded test database when given.
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
    # Public base URL of the service; the callback URL handed to the IdP is
    # derived from this (config-driven, not request.base_url).
    monkeypatch.setenv("OHE_BASE_URL", "http://test")
    # Keep the background cleanup loop out of the test process.
    monkeypatch.setenv("OHE_CLEANUP_INTERVAL", "0")
    # Keep the LLM usage background loops out of the test process.
    monkeypatch.setenv("OHE_LLM_USAGE_PARTITION_INTERVAL", "0")
    monkeypatch.setenv("OHE_LLM_USAGE_AGGREGATE_INTERVAL", "0")
    # Keep the MCP usage background loops out of the test process.
    monkeypatch.setenv("OHE_MCP_USAGE_PARTITION_INTERVAL", "0")
    monkeypatch.setenv("OHE_MCP_USAGE_AGGREGATE_INTERVAL", "0")


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
async def engine(
    monkeypatch: pytest.MonkeyPatch,
    pg_server: PostgreSQLExecutor,
    request: pytest.FixtureRequest,
) -> AsyncGenerator[AsyncEngine, None]:
    """A per-test async engine bound to a fresh database cloned from the template.

    The schema already exists in the cloned database (built once into the
    session template), so no ``create_all``/``drop_all`` runs per test. Each
    test gets a uniquely-named database cloned from the template, dropped after
    the test.
    """
    proc = pg_server
    host = proc.host
    port = proc.port
    user = proc.user
    password = proc.password or ""
    template_dbname = proc.template_dbname
    # Unique per-test database name so parallel/sequential tests never collide.
    test_dbname = (
        f"test_{request.node.nodeid.replace('/', '_').replace(':', '_')}_{uuid.uuid4().hex[:8]}"
    )
    # Clamp to Postgres' 63-byte identifier limit.
    test_dbname = test_dbname[:63]
    # Clone the template into the per-test database. The janitor terminates
    # stray template connections before the CLONE and drops the clone on exit.
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
    _set_test_config(
        monkeypatch,
        host=host,
        port=str(port),
        db_name=test_dbname,
        username=user,
        password=password,
    )
    url = f"postgresql+asyncpg://{user}:{password}@{host}:{port}/{test_dbname}"
    eng = create_async_engine(url)
    yield eng
    await eng.dispose()
    janitor.drop()
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
    ``Authorization: Bearer`` header (the cookie/ACCESS_TOKEN JWE path) so
    permission dependencies see a real principal. The ``X-API-Key`` header is
    reserved for opaque API keys and is not used by the default test client.
    """
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
