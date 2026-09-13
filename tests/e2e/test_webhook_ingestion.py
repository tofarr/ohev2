"""E2E test: legacy agent-server webhook ingestion (tofarr/ohev2#125).

Seeds the database with the admin user and a sandbox config, mints a system
API key with a known plaintext directly in the DB, then verifies over HTTP
that:

1. ``POST /webhooks/{sandbox_config_id}/conversations`` authenticated via
   ``X-API-Key`` creates the conversation (idempotent upsert: a second call
   updates title/metrics instead of duplicating the row) for the sandbox
   identified by the URL.
2. ``POST /webhooks/{sandbox_config_id}/conversations/{id}/events`` appends
   events and folds a stats snapshot into the conversation's metric columns.
3. An unknown API key is rejected (401) and events for a conversation
   owned by another sandbox are rejected (404).

Run: uv run pytest tests/e2e -q
Requires the app + Postgres to be up (``docker compose up -d``) and migrations
applied (``uv run alembic upgrade head``).
"""

from __future__ import annotations

import os
import uuid

import httpx
from openhands.agent_server.models import ConversationInfo
from openhands.sdk import LLM, Agent
from openhands.sdk.conversation.conversation_stats import ConversationStats
from openhands.sdk.event import ConversationStateUpdateEvent, MessageEvent
from openhands.sdk.llm import TokenUsage
from openhands.sdk.llm.utils.metrics import Metrics
from openhands.sdk.workspace import LocalWorkspace
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from openhands.ev2.auth.auth_models import ApiKey
from openhands.ev2.auth.auth_tokens import hash_api_key_value
from openhands.ev2.conversation.conversation_models import Conversation
from openhands.ev2.event.event_models import Event
from openhands.ev2.role.role_models import UserRole
from openhands.ev2.sandbox.sandbox_config_models import SandboxConfig
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

COOKIE_NAME = os.environ.get("OHE_AUTH_COOKIE_NAME", "ohesession")

API_KEY_VALUE = f"oh_{uuid.uuid4().hex}"


async def _login(client: httpx.AsyncClient, username: str, password: str) -> str:
    """Log in via the dev IdP and return the session cookie value."""
    resp = await client.post(
        "/auth/dev/login",
        json={"username": username, "password": password},
    )
    assert resp.status_code == 200, resp.text
    return resp.cookies[COOKIE_NAME]


def _api_key_headers(key: str = API_KEY_VALUE) -> dict[str, str]:
    return {"X-API-Key": key}


async def _reset_e2e_artifacts(session: AsyncSession) -> None:
    """Delete rows from prior runs so the test is hermetic across re-runs."""
    await session.execute(delete(ApiKey))
    await session.execute(delete(Event))
    await session.execute(delete(Conversation))
    await session.execute(delete(SandboxConfig))
    await session.execute(delete(SandboxTemplate))
    user = (
        await session.execute(select(User).where(User.username == ADMIN_USERNAME))
    ).scalar_one_or_none()
    if user is not None:
        await session.execute(delete(UserRole).where(UserRole.user_id == user.id))
        await session.execute(delete(User).where(User.id == user.id))
    await session.commit()


async def _seed(session: AsyncSession) -> tuple[uuid.UUID, uuid.UUID]:
    """Seed the admin user and a sandbox config; return (admin_id, config_id)."""
    admin, _ = await seed_db(
        session,
        admin_username=ADMIN_USERNAME,
        admin_email="admin@example.com",
        admin_password=ADMIN_PASSWORD,
    )
    template = SandboxTemplate(
        creator_id=admin.id,
        docker_image_tag=f"example/agent-server:{uuid.uuid4()}",
    )
    session.add(template)
    await session.flush()
    config = SandboxConfig(
        creator_id=admin.id,
        sandbox_template_id=template.id,
        session_api_key="encrypted-session-key",
    )
    session.add(config)
    await session.flush()
    # The principal authenticates as the config's owner with a raw API key;
    # the webhook route carries the sandbox config id in its path.
    session.add(
        ApiKey(
            key_hash=hash_api_key_value(API_KEY_VALUE),
            prefix=API_KEY_VALUE[:7],
            creator_id=admin.id,
            name=f"Sandbox {config.id} API Key",
            system=True,
        )
    )
    await session.flush()
    await session.commit()
    return admin.id, config.id


def _conversation_info_payload(conversation_id: uuid.UUID, title: str) -> dict:
    llm = LLM(model="test-model", usage_id="test-llm")
    info = ConversationInfo(
        id=conversation_id,
        agent=Agent(llm=llm, tools=[]),
        workspace=LocalWorkspace(working_dir="/tmp/workspace"),
        title=title,
        execution_status="running",
    )
    return info.model_dump(mode="json", by_alias=True)


def _event_payloads() -> list[dict]:
    message = MessageEvent(
        source="user",
        llm_message={"role": "user", "content": [{"type": "text", "text": "hello"}]},
    )
    stats = ConversationStats(
        usage_to_metrics={
            "test-llm": Metrics(
                model_name="test-model",
                accumulated_cost=0.75,
                accumulated_token_usage=TokenUsage(
                    model="test-model",
                    prompt_tokens=40,
                    completion_tokens=20,
                ),
            )
        }
    )
    stats_event = ConversationStateUpdateEvent(
        source="agent", key="stats", value=stats.model_dump(mode="json")
    )
    return [
        message.model_dump(mode="json"),
        stats_event.model_dump(mode="json"),
    ]


async def test_webhook_ingestion() -> None:
    db_url = f"postgresql+asyncpg://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    engine = create_async_engine(db_url)
    config_id: uuid.UUID | None = None
    try:
        factory = async_sessionmaker(engine, expire_on_commit=False)
        async with factory() as session:
            await _reset_e2e_artifacts(session)
            _, config_id = await _seed(session)
    finally:
        await engine.dispose()
    assert config_id is not None

    conversation_id = uuid.uuid4()
    async with httpx.AsyncClient(base_url=BASE_URL) as ac:
        # Unknown API keys are rejected.
        bad = await ac.post(
            f"/webhooks/{config_id}/conversations",
            headers=_api_key_headers("bogus"),
            json=_conversation_info_payload(conversation_id, "denied"),
        )
        assert bad.status_code == 401, bad.text

        # The system API key creates the conversation.
        created = await ac.post(
            f"/webhooks/{config_id}/conversations",
            headers=_api_key_headers(),
            json=_conversation_info_payload(conversation_id, "e2e webhook conversation"),
        )
        assert created.status_code == 200, created.text

        # A second call with the same id upserts (renames) instead of
        # duplicating.
        renamed = await ac.post(
            f"/webhooks/{config_id}/conversations",
            headers=_api_key_headers(),
            json=_conversation_info_payload(conversation_id, "renamed"),
        )
        assert renamed.status_code == 200, renamed.text

        # Events append; the stats snapshot folds into the conversation metrics.
        events = await ac.post(
            f"/webhooks/{config_id}/conversations/{conversation_id}/events",
            headers=_api_key_headers(),
            json=_event_payloads(),
        )
        assert events.status_code == 200, events.text

        # Events for an unknown/foreign conversation are rejected.
        foreign = await ac.post(
            f"/webhooks/{config_id}/conversations/{uuid.uuid4()}/events",
            headers=_api_key_headers(),
            json=_event_payloads(),
        )
        assert foreign.status_code == 404, foreign.text

        # The admin sees exactly one conversation with the folded metrics.
        cookie = await _login(ac, ADMIN_USERNAME, ADMIN_PASSWORD)
        headers = {"Cookie": f"{COOKIE_NAME}={cookie}"}
        listing = await ac.get("/conversations", headers=headers)
        assert listing.status_code == 200, listing.text
        items = listing.json()["items"]
        assert len(items) == 1
        row = items[0]
        assert row["id"] == str(conversation_id)
        assert row["title"] == "renamed"
        assert row["llm_model"] == "test-model"
        assert row["accumulated_cost"] == 0.75
        assert row["prompt_tokens"] == 40
        assert row["completion_tokens"] == 20
        assert row["total_tokens"] == 60

        event_listing = await ac.get(f"/conversations/{conversation_id}/events", headers=headers)
        assert event_listing.status_code == 200, event_listing.text
        assert len(event_listing.json()["items"]) == 2
