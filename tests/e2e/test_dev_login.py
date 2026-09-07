"""E2E test: dev login sets a usable session cookie.

Seeds the database with ``seed_db`` (default admin credentials), logs in via
``POST /auth/dev/login``, and verifies the resulting session cookie
authenticates a subsequent ``GET /users`` request — i.e. the cookie is real
and carries the admin principal's permissions.

Run: uv run pytest tests/e2e -q
Requires the app + Postgres to be up (``docker compose up -d``) and migrations
applied (``uv run alembic upgrade head``).
"""

from __future__ import annotations

import os

import httpx
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from openhands.ev2.scripts.seed_db import seed_db

BASE_URL = os.environ.get("OHE_BASE_URL", "http://localhost:8000")

# Database coordinates for seeding. Default to the docker-compose service
# (Postgres exposed on localhost:5432, user/db ``ohev``). Override via env for
# non-default deployments.
DB_HOST = os.environ.get("OHE_DB_CONFIG_HOST", "localhost")
DB_PORT = os.environ.get("OHE_DB_CONFIG_PORT", "5432")
DB_NAME = os.environ.get("OHE_DB_CONFIG_DB_NAME", "ohev")
DB_USER = os.environ.get("OHE_DB_CONFIG_USERNAME", "ohev")
DB_PASSWORD = os.environ.get("OHE_DB_CONFIG_PASSWORD", "ohev")

# Default admin credentials produced by seed_db (unless OHE_SEED_ADMIN_* set).
ADMIN_USERNAME = os.environ.get("OHE_SEED_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("OHE_SEED_ADMIN_PASSWORD", "changeme")


async def test_dev_login_sets_usable_session_cookie() -> None:
    # 1. Seed the database so a real enabled user exists to log in as.
    db_url = f"postgresql+asyncpg://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    engine = create_async_engine(db_url)
    try:
        factory = async_sessionmaker(engine, expire_on_commit=False)
        async with factory() as session:
            admin, _regular = await seed_db(
                session,
                admin_username=ADMIN_USERNAME,
                admin_email="admin@example.com",
                admin_password=ADMIN_PASSWORD,
                user_username="user",
                user_email="user@example.com",
                user_password="changeme",
            )
            admin_id = admin.id
    finally:
        await engine.dispose()

    async with httpx.AsyncClient(base_url=BASE_URL) as ac:
        # 2. Log in via the dev login endpoint and capture the session cookie.
        login_resp = await ac.post(
            "/auth/dev/login",
            json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
        )
        assert login_resp.status_code == 200, login_resp.text
        assert login_resp.json()["username"] == ADMIN_USERNAME

        set_cookie = login_resp.headers.get("set-cookie")
        assert set_cookie, "login response did not set a session cookie"
        # The cookie is Secure-flagged; extract the value explicitly rather than
        # relying on the cookie jar (which drops Secure cookies over http).
        cookie_name = os.environ.get("OHE_AUTH_COOKIE_NAME", "ohesession")
        cookie_value = _extract_cookie(set_cookie, cookie_name)
        assert cookie_value, f"session cookie {cookie_name!r} not found in Set-Cookie"

        # 3. The cookie must authenticate a privileged request: search users.
        users_resp = await ac.get(
            "/users",
            headers={"Cookie": f"{cookie_name}={cookie_value}"},
        )
        assert users_resp.status_code == 200, users_resp.text
        items = users_resp.json()["items"]
        usernames = {u["username"] for u in items}
        assert ADMIN_USERNAME in usernames
        assert any(u["id"] == str(admin_id) for u in items)


def _extract_cookie(set_cookie: str, name: str) -> str | None:
    """Pull ``<name>=<value>`` out of a Set-Cookie header value."""
    for part in set_cookie.split(";"):
        part = part.strip()
        if part.startswith(f"{name}="):
            return part[len(name) + 1 :]
    return None
