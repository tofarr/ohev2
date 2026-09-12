"""E2E test: ConversationAccess grants scoped read/search, denies writes.

Seeds the database with the admin user and a regular user (whose seeded
``user`` role carries ``conversation_permission = ConversationAccess``),
inserts sandbox configs + conversations for each directly in the DB (the
sandbox provider is not exercised here), then verifies over HTTP that:

1. The admin can create/read/update/delete conversations (full CRUD).
2. The regular user can search/read only the conversations backed by sandbox
   configs they created.
3. The regular user is denied (403) create/update/delete.

Run: uv run pytest tests/e2e -q
Requires the app + Postgres to be up (``docker compose up -d``) and migrations
applied (``uv run alembic upgrade head``).
"""

from __future__ import annotations

import os
import uuid

import httpx
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from openhands.ev2.conversation.conversation_models import Conversation
from openhands.ev2.role.role_models import UserRole
from openhands.ev2.sandbox.sandbox_config_models import SandboxConfig
from openhands.ev2.sandbox.sandbox_session import hash_session_api_key
from openhands.ev2.sandbox.sandbox_template_models import SandboxTemplate
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

USER_USERNAME = os.environ.get("OHE_SEED_USER_USERNAME", "user")
USER_PASSWORD = os.environ.get("OHE_SEED_USER_PASSWORD", "changeme")

COOKIE_NAME = os.environ.get("OHE_AUTH_COOKIE_NAME", "ohesession")


async def _login(client: httpx.AsyncClient, username: str, password: str) -> str:
    """Log in via the dev IdP and return the session cookie value."""
    resp = await client.post(
        "/auth/dev/login",
        json={"username": username, "password": password},
    )
    assert resp.status_code == 200, resp.text
    return resp.cookies[COOKIE_NAME]


def _headers(cookie: str) -> dict[str, str]:
    return {"Cookie": f"{COOKIE_NAME}={cookie}"}


async def _make_sandbox_config(session: AsyncSession, creator_id: uuid.UUID) -> SandboxConfig:
    template = SandboxTemplate(
        creator_id=creator_id,
        docker_image_tag=f"example/agent-server:{uuid.uuid4()}",
    )
    session.add(template)
    await session.flush()
    config = SandboxConfig(
        creator_id=creator_id,
        sandbox_template_id=template.id,
        session_api_key="encrypted-session-key",
        session_api_key_hash=hash_session_api_key(f"session-key-{creator_id}"),
    )
    session.add(config)
    await session.flush()
    return config


async def _reset_e2e_artifacts(session: AsyncSession) -> None:
    """Delete rows from prior runs so the test is hermetic across re-runs."""
    await session.execute(delete(Conversation))
    await session.execute(delete(SandboxConfig))
    await session.execute(delete(SandboxTemplate))
    for username in (ADMIN_USERNAME, USER_USERNAME):
        user = (
            await session.execute(select(User).where(User.username == username))
        ).scalar_one_or_none()
        if user is not None:
            await session.execute(delete(UserRole).where(UserRole.user_id == user.id))
            await session.execute(delete(User).where(User.id == user.id))
    await session.commit()


async def test_conversation_access_policy() -> None:
    db_url = f"postgresql+asyncpg://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    engine = create_async_engine(db_url)
    try:
        factory = async_sessionmaker(engine, expire_on_commit=False)
        async with factory() as session:
            await _reset_e2e_artifacts(session)
            admin, regular = await seed_db(
                session,
                admin_username=ADMIN_USERNAME,
                admin_email="admin@example.com",
                admin_password=ADMIN_PASSWORD,
                user_username=USER_USERNAME,
                user_email="user@example.com",
                user_password=USER_PASSWORD,
            )
            assert regular is not None
            user_config = await _make_sandbox_config(session, regular.id)
            admin_config = await _make_sandbox_config(session, admin.id)
            await session.commit()
    finally:
        await engine.dispose()

    async with httpx.AsyncClient(base_url=BASE_URL) as ac:
        admin_cookie = await _login(ac, ADMIN_USERNAME, ADMIN_PASSWORD)
        user_cookie = await _login(ac, USER_USERNAME, USER_PASSWORD)
        admin_headers = _headers(admin_cookie)
        user_headers = _headers(user_cookie)

        def _payload(config_id: uuid.UUID, title: str) -> dict[str, str]:
            return {
                "title": title,
                "sandbox_config_id": str(config_id),
                "llm_model": "claude-sonnet-4",
                "agent_kind": "openhands",
                "selected_repository": "org/repo",
                "selected_branch": "main",
                "trigger": "manual",
            }

        # Admin creates one conversation per sandbox config.
        own_resp = await ac.post(
            "/conversations",
            json=_payload(user_config.id, "user conversation"),
            headers=admin_headers,
        )
        assert own_resp.status_code == 201, own_resp.text
        own = own_resp.json()
        foreign_resp = await ac.post(
            "/conversations",
            json=_payload(admin_config.id, "admin conversation"),
            headers=admin_headers,
        )
        assert foreign_resp.status_code == 201, foreign_resp.text
        foreign = foreign_resp.json()

        # The regular user sees only the conversation backed by their own
        # sandbox config.
        list_resp = await ac.get("/conversations", headers=user_headers)
        assert list_resp.status_code == 200, list_resp.text
        assert [i["id"] for i in list_resp.json()["items"]] == [own["id"]]
        assert (
            await ac.get(f"/conversations/{own['id']}", headers=user_headers)
        ).status_code == 200
        # Out-of-scope conversations are invisible (404, not 403).
        assert (
            await ac.get(f"/conversations/{foreign['id']}", headers=user_headers)
        ).status_code == 404

        # Writes are denied for the regular user, even on in-scope rows.
        assert (
            await ac.post(
                "/conversations", json=_payload(user_config.id, "nope"), headers=user_headers
            )
        ).status_code == 403
        assert (
            await ac.patch(
                f"/conversations/{own['id']}", json={"title": "nope"}, headers=user_headers
            )
        ).status_code == 403
        assert (
            await ac.delete(f"/conversations/{own['id']}", headers=user_headers)
        ).status_code == 403

        # The admin PATCHes the metric columns (as the ingestion path will).
        patch_resp = await ac.patch(
            f"/conversations/{own['id']}",
            json={
                "accumulated_cost": 0.5,
                "prompt_tokens": 10,
                "completion_tokens": 5,
                "total_tokens": 15,
            },
            headers=admin_headers,
        )
        assert patch_resp.status_code == 200, patch_resp.text
        assert patch_resp.json()["total_tokens"] == 15
