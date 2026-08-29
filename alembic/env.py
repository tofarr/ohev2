"""Alembic migration environment.

Configured for async SQLAlchemy. Migrations run against the configured
DATABASE_URL. Import model metadata here so autogenerate detects changes.
"""

import asyncio
import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

# Import models so Alembic autogenerate sees their metadata.
from openhands.ev2.auth.auth_models import (  # noqa: F401
    ApiKey,
    IdpRefreshToken,
    OAuthClient,
    OAuthClientRedirectUri,
    RefreshToken,
)
from openhands.ev2.db import Base
from openhands.ev2.feature_flag.feature_flag_models import (  # noqa: F401
    FeatureFlag,
    FeatureFlagRole,
)
from openhands.ev2.user.user_models import User  # noqa: F401

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)


def _db_url_from_env() -> str | None:
    """Assemble the SQLAlchemy URL from the OHE_DB_CONFIG_* env vars.

    Done without loading the full AppConfig so alembic can run with only the
    database variables set (the app config requires IdP / encryption fields
    that are irrelevant to migrations). A plain DATABASE_URL wins as an escape
    hatch for one-off runs.
    """
    if os.environ.get("DATABASE_URL"):
        return os.environ["DATABASE_URL"]
    host = os.environ.get("OHE_DB_CONFIG_HOST")
    if host is None:
        return None
    port = os.environ.get("OHE_DB_CONFIG_PORT", "5432")
    db_name = os.environ.get("OHE_DB_CONFIG_DB_NAME", "ohev")
    username = os.environ.get("OHE_DB_CONFIG_USERNAME", "ohev")
    password = os.environ.get("OHE_DB_CONFIG_PASSWORD", "ohev")
    return f"postgresql+asyncpg://{username}:{password}@{host}:{port}/{db_name}"


_db_url = _db_url_from_env()
if _db_url:
    config.set_main_option("sqlalchemy.url", _db_url)


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(url=url, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=Base.metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
