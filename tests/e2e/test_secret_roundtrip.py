"""E2E test: create a secret as admin and reveal its value.

Seeds the database with the admin user (all permissions via ``seed_db``),
logs in as the admin via ``POST /auth/dev/login``, then exercises the secrets
surface over HTTP:

1. ``POST /secrets`` creates a secret — the response carries metadata only
   (never the value).
2. ``GET /secrets/{id}`` returns the same metadata.
3. ``GET /secret-values/{id}`` reveals the decrypted plaintext, which must
   match the value supplied on create.
4. ``DELETE /secrets/{id}`` removes the secret (and the next reveal is 404).

Run: uv run pytest tests/e2e -q
Requires the app + Postgres to be up (``docker compose up -d``) and migrations
applied (``uv run alembic upgrade head``).
"""

from __future__ import annotations

import os

import httpx
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from openhands.ev2.scripts.seed_db import seed_db
from openhands.ev2.secret.sql_secrets_models import SqlSecret

BASE_URL = os.environ.get("OHE_BASE_URL", "http://localhost:8000")

DB_HOST = os.environ.get("OHE_DB_CONFIG_HOST", "localhost")
DB_PORT = os.environ.get("OHE_DB_CONFIG_PORT", "5432")
DB_NAME = os.environ.get("OHE_DB_CONFIG_DB_NAME", "ohev")
DB_USER = os.environ.get("OHE_DB_CONFIG_USERNAME", "ohev")
DB_PASSWORD = os.environ.get("OHE_DB_CONFIG_PASSWORD", "ohev")

ADMIN_USERNAME = os.environ.get("OHE_SEED_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("OHE_SEED_ADMIN_PASSWORD", "changeme")

COOKIE_NAME = os.environ.get("OHE_AUTH_COOKIE_NAME", "ohesession")

SECRET_CODE = "E2E_API_KEY"
SECRET_VALUE = "e2e-secret-value-hunter2"


async def test_admin_can_create_and_reveal_a_secret() -> None:
    # 1. Seed the admin so a real enabled user exists to log in as. Clean up
    #    any prior-run secret first so a re-run cannot hit a 409 on the code.
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
        cookie = await _login(ac, ADMIN_USERNAME, ADMIN_PASSWORD)
        headers = {"Cookie": f"{COOKIE_NAME}={cookie}"}

        # 2. Create the secret. The metadata response must never carry the value.
        create_resp = await ac.post(
            "/secrets",
            json={"code": SECRET_CODE, "value": SECRET_VALUE, "description": "e2e"},
            headers=headers,
        )
        assert create_resp.status_code == 201, create_resp.text
        created = create_resp.json()
        assert created["code"] == SECRET_CODE
        assert "value" not in created
        secret_id = created["id"]

        # 3. The same metadata is retrievable from /secrets/{id}.
        get_resp = await ac.get(f"/secrets/{secret_id}", headers=headers)
        assert get_resp.status_code == 200, get_resp.text
        assert get_resp.json()["code"] == SECRET_CODE
        assert "value" not in get_resp.json()

        # 4. The /secret-values projection reveals the exact value created.
        reveal_resp = await ac.get(f"/secret-values/{secret_id}", headers=headers)
        assert reveal_resp.status_code == 200, reveal_resp.text
        revealed = reveal_resp.json()
        assert revealed["id"] == secret_id
        assert revealed["code"] == SECRET_CODE
        assert revealed["value"] == SECRET_VALUE

        # 5. Cleanup: deleting the secret also removes the revealable value.
        delete_resp = await ac.delete(f"/secrets/{secret_id}", headers=headers)
        assert delete_resp.status_code == 204, delete_resp.text
        gone_resp = await ac.get(f"/secret-values/{secret_id}", headers=headers)
        assert gone_resp.status_code == 404, gone_resp.text


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
    """Delete the prior run's secret so the test is hermetic across re-runs.

    The secret is created over the API and is not idempotent — a re-run would
    hit a 409 on the unique ``code``. Deleting it first (the FK cascades the
    detail row) keeps the test hermetic.
    """
    await session.execute(delete(SqlSecret).where(SqlSecret.code == SECRET_CODE))
    await session.commit()


def _extract_cookie(set_cookie: str, name: str) -> str | None:
    """Pull ``<name>=<value>`` out of a Set-Cookie header value."""
    for part in set_cookie.split(";"):
        part = part.strip()
        if part.startswith(f"{name}="):
            return part[len(name) + 1 :]
    return None
