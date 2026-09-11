"""E2E test: a read-only role grants user read and denies user create.

Seeds the database with the admin user (all permissions via ``seed_db``), logs
in as the admin via ``POST /auth/dev/login``, then exercises the full RBAC
flow over HTTP:

1. As admin, create a ``restricted`` user.
2. As admin, create a ``restricted`` role granting :class:`ReadOnly` on
   ``user_permission`` (and nothing else).
3. As admin, assign the role to the restricted user via ``/user-roles``.
4. Log in as the restricted user (dev login) and verify:
   * ``GET /users`` succeeds (read/search is allowed).
   * ``POST /users`` is denied (403) — create is not granted by ``ReadOnly``.

Run: uv run pytest tests/e2e -q
Requires the app + Postgres to be up (``docker compose up -d``) and migrations
applied (``uv run alembic upgrade head``).
"""

from __future__ import annotations

import os

import httpx
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from openhands.ev2.role.role_models import Role, UserRole
from openhands.ev2.scripts.seed_db import seed_db
from openhands.ev2.user.user_models import User

BASE_URL = os.environ.get("OHE_BASE_URL", "http://localhost:8000")

DB_HOST = os.environ.get("OHE_DB_CONFIG_HOST", "localhost")
DB_PORT = os.environ.get("OHE_DB_CONFIG_PORT", "5432")
DB_NAME = os.environ.get("OHE_DB_CONFIG_DB_NAME", "ohev")
DB_USER = os.environ.get("OHE_DB_CONFIG_USERNAME", "ohev")
DB_PASSWORD = os.environ.get("OHE_DB_CONFIG_PASSWORD", "ohev")

ADMIN_USERNAME = os.environ.get("OHE_SEED_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("OHE_SEED_ADMIN_PASSWORD", "changeme")

COOKIE_NAME = os.environ.get("OHE_AUTH_COOKIE_NAME", "ohesession")

RESTRICTED_USERNAME = "restricted"
RESTRICTED_EMAIL = "restricted@example.com"
RESTRICTED_PASSWORD = "changeme"
RESTRICTED_ROLE_NAME = "restricted"


async def test_restricted_user_can_read_but_not_create_users() -> None:
    # 1. Seed the admin so a real enabled user exists to bootstrap with.
    # Clean up any prior-run artifacts first so the test is hermetic across
    # re-runs: deleting the user/role cascades the user_role assignment row.
    db_url = f"postgresql+asyncpg://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    engine = create_async_engine(db_url)
    try:
        factory = async_sessionmaker(engine, expire_on_commit=False)
        async with factory() as session:
            await _reset_e2e_artifacts(session)
            await seed_db(
                session,
                admin_username=ADMIN_USERNAME,
                admin_email="admin@example.com",
                admin_password=ADMIN_PASSWORD,
            )
    finally:
        await engine.dispose()

    async with httpx.AsyncClient(base_url=BASE_URL) as ac:
        admin_cookie = await _login(ac, ADMIN_USERNAME, ADMIN_PASSWORD)

        # 2. As admin, create the restricted user.
        create_resp = await ac.post(
            "/users",
            json={
                "username": RESTRICTED_USERNAME,
                "email": RESTRICTED_EMAIL,
                "password": RESTRICTED_PASSWORD,
                "enabled": True,
            },
            headers={"Cookie": f"{COOKIE_NAME}={admin_cookie}"},
        )
        assert create_resp.status_code == 201, create_resp.text
        restricted_user = create_resp.json()
        restricted_user_id = restricted_user["id"]

        # 3. As admin, create the restricted role: ReadOnly on user_permission
        #    only; every other governed entity stays null (deny).
        role_resp = await ac.post(
            "/roles",
            json={
                "name": RESTRICTED_ROLE_NAME,
                "user_permission": {"kind": "ReadOnly"},
            },
            headers={"Cookie": f"{COOKIE_NAME}={admin_cookie}"},
        )
        assert role_resp.status_code == 201, role_resp.text
        restricted_role_id = role_resp.json()["id"]

        # 4. As admin, assign the restricted role to the restricted user.
        assign_resp = await ac.post(
            "/user-roles",
            json={"role_id": restricted_role_id, "user_id": restricted_user_id},
            headers={"Cookie": f"{COOKIE_NAME}={admin_cookie}"},
        )
        assert assign_resp.status_code == 201, assign_resp.text

        # 5. Log in as the restricted user and exercise its permissions.
        restricted_cookie = await _login(ac, RESTRICTED_USERNAME, RESTRICTED_PASSWORD)
        restricted_headers = {"Cookie": f"{COOKIE_NAME}={restricted_cookie}"}

        # Read access to the user collection is granted by ReadOnly.
        list_resp = await ac.get("/users", headers=restricted_headers)
        assert list_resp.status_code == 200, list_resp.text
        usernames = {u["username"] for u in list_resp.json()["items"]}
        assert RESTRICTED_USERNAME in usernames

        # Create is denied: ReadOnly grants only READ/SEARCH, so a new user
        # create must be rejected (403, never 201).
        denied_resp = await ac.post(
            "/users",
            json={
                "username": "should_not_succeed",
                "email": "nope@example.com",
                "password": "changeme",
                "enabled": True,
            },
            headers=restricted_headers,
        )
        assert denied_resp.status_code == 403, denied_resp.text


async def _login(client: httpx.AsyncClient, username: str, password: str) -> str:
    """Log in via the dev IdP and return the session cookie value."""
    resp = await client.post(
        "/auth/dev/login",
        json={"username": username, "password": password},
    )
    assert resp.status_code == 200, resp.text
    set_cookie = resp.headers.get("set-cookie")
    assert set_cookie, "login response did not set a session cookie"
    cookie = _extract_cookie(set_cookie, COOKIE_NAME)
    assert cookie, f"session cookie {COOKIE_NAME!r} not found in Set-Cookie"
    return cookie


async def _reset_e2e_artifacts(session: AsyncSession) -> None:
    """Delete prior-run users/roles created by this test (cascades user_roles).

    seed_db upserts the admin user/role idempotently, but the restricted
    user, role, and their assignment are created over the API and are not
    idempotent — a re-run would hit a 409. Deleting them first (the FKs
    cascade the user_role link) keeps the test hermetic across re-runs.
    """
    user = await session.scalar(select(User).where(User.username == RESTRICTED_USERNAME))
    if user is not None:
        await session.execute(delete(UserRole).where(UserRole.user_id == user.id))
        await session.delete(user)
    role = await session.scalar(select(Role).where(Role.name == RESTRICTED_ROLE_NAME))
    if role is not None:
        await session.execute(delete(UserRole).where(UserRole.role_id == role.id))
        await session.delete(role)
    await session.commit()


def _extract_cookie(set_cookie: str, name: str) -> str | None:
    """Pull ``<name>=<value>`` out of a Set-Cookie header value."""
    for part in set_cookie.split(";"):
        part = part.strip()
        if part.startswith(f"{name}="):
            return part[len(name) + 1 :]
    return None
