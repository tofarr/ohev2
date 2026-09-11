"""E2E test: sandbox create → agent-server access → snapshot → restore → cleanup.

Seeds the database with ``seed_db`` (default admin credentials, all permissions),
logs in as the admin via ``POST /auth/dev/login``, then exercises the full
sandbox lifecycle over HTTP against the real Docker backend:

1. Create a sandbox template (agent-server image).
2. Create a sandbox config + live sandbox from that template.
3. Wait for the sandbox to become ``active`` and probe the agent-server
   ``/api/conversations/search`` endpoint inside the container.
4. Capture a workspace snapshot from the live sandbox.
5. Delete the sandbox.
6. Create a new sandbox from the snapshot (``snapshot_id`` on ``SandboxCreate``).
7. Probe the agent-server conversations endpoint on the restored sandbox.
8. Clean up: delete both the restored sandbox and the snapshot.

Run: uv run pytest tests/e2e -q
Requires the app + Postgres to be up (``docker compose up -d``) and migrations
applied (``uv run alembic upgrade head``). The Docker daemon must be reachable
from the app process (Docker-in-Docker socket bind-mount in docker-compose).
"""

from __future__ import annotations

import asyncio
import os
import uuid
from typing import Any

import httpx
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from openhands.ev2.scripts.seed_db import seed_db

BASE_URL = os.environ.get("OHE_BASE_URL", "http://localhost:8000")

DB_HOST = os.environ.get("OHE_DB_CONFIG_HOST", "localhost")
DB_PORT = os.environ.get("OHE_DB_CONFIG_PORT", "5432")
DB_NAME = os.environ.get("OHE_DB_CONFIG_DB_NAME", "ohev")
DB_USER = os.environ.get("OHE_DB_CONFIG_USERNAME", "ohev")
DB_PASSWORD = os.environ.get("OHE_DB_CONFIG_PASSWORD", "ohev")

ADMIN_USERNAME = os.environ.get("OHE_SEED_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("OHE_SEED_ADMIN_PASSWORD", "changeme")
COOKIE_NAME = os.environ.get("OHE_AUTH_COOKIE_NAME", "ohesession")

# The agent-server image. Override via env to pin a specific tag. There is no
# `latest` tag in the GHCR registry; `main-python` is the python-runtime variant
# built from the agent-server main branch (the closest equivalent to "latest").
AGENT_SERVER_IMAGE = os.environ.get(
    "OHE_E2E_AGENT_SERVER_IMAGE",
    "ghcr.io/openhands/agent-server:main-python",
)

_POLL_INTERVAL = 2.0
_POLL_TIMEOUT = 120.0
# The agent server inside a freshly-started container needs a few seconds to
# accept requests after Docker reports the container as "running". Retrying
# with backoff bridges this gap without a fragile fixed sleep.
_PROBE_RETRIES = 15
_PROBE_INTERVAL = 2.0


async def test_sandbox_snapshot_lifecycle() -> None:
    # 1. Seed the admin so a real enabled user exists to bootstrap with.
    db_url = f"postgresql+asyncpg://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    engine = create_async_engine(db_url)
    try:
        factory = async_sessionmaker(engine, expire_on_commit=False)
        async with factory() as session:
            await seed_db(
                session,
                admin_username=ADMIN_USERNAME,
                admin_email="admin@example.com",
                admin_password=ADMIN_PASSWORD,
            )
    finally:
        await engine.dispose()

    async with httpx.AsyncClient(base_url=BASE_URL, timeout=60.0) as ac:
        admin_cookie = await _login(ac, ADMIN_USERNAME, ADMIN_PASSWORD)
        headers = {"Cookie": f"{COOKIE_NAME}={admin_cookie}"}

        # 2. Create a sandbox template with the agent-server image.
        template_id = await _create_template(ac, headers, AGENT_SERVER_IMAGE)

        # 3. Create a sandbox config (enabled so the sandbox starts).
        config_id = await _create_config(ac, headers, template_id)

        # 4. Create the live sandbox.
        sandbox1 = await _create_sandbox(ac, headers, template_id, config_id)
        sandbox1_id = sandbox1["id"]

        try:
            # 5. Wait for the sandbox to become active and probe the agent server.
            await _wait_for_active(ac, headers, sandbox1_id)
            await _probe_conversations(ac, headers, sandbox1_id)

            # 6. Capture a snapshot from the live sandbox.
            snapshot_id = await _capture_snapshot(ac, headers, template_id, sandbox1_id)
        finally:
            # 7. Delete the first sandbox (cleanup even if snapshot fails).
            await _delete_sandbox(ac, headers, sandbox1_id)

        # 8. Create a new sandbox from the snapshot.
        sandbox2 = await _create_sandbox(
            ac, headers, template_id, config_id, snapshot_id=snapshot_id
        )
        sandbox2_id = sandbox2["id"]

        try:
            # 9. Wait for the restored sandbox and probe the agent server.
            await _wait_for_active(ac, headers, sandbox2_id)
            await _probe_conversations(ac, headers, sandbox2_id)
        finally:
            # 10. Clean up: delete the restored sandbox and the snapshot.
            await _delete_sandbox(ac, headers, sandbox2_id)
            await _delete_snapshot(ac, headers, snapshot_id)


# --------------------------------------------------------------------------- #
# Helpers.
# --------------------------------------------------------------------------- #


async def _login(client: httpx.AsyncClient, username: str, password: str) -> str:
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


async def _create_template(
    client: httpx.AsyncClient, headers: dict[str, str], image_tag: str
) -> uuid.UUID:
    resp = await client.post(
        "/sandbox/sandbox-templates",
        json={
            "docker_image_tag": image_tag,
            "working_dir": "/home/openhands",
            "snapshot_on_deactivate": False,
        },
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    return uuid.UUID(resp.json()["id"])


async def _create_config(
    client: httpx.AsyncClient, headers: dict[str, str], template_id: uuid.UUID
) -> str:
    resp = await client.post(
        "/sandbox/sandbox-configs",
        json={
            "sandbox_template_id": str(template_id),
            "enabled": True,
        },
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    return str(resp.json()["id"])


async def _create_sandbox(
    client: httpx.AsyncClient,
    headers: dict[str, str],
    template_id: uuid.UUID,
    config_id: str,
    *,
    snapshot_id: uuid.UUID | None = None,
) -> dict[str, Any]:
    payload: dict[str, str] = {
        "sandbox_template_id": str(template_id),
        "sandbox_config_id": config_id,
    }
    if snapshot_id is not None:
        payload["snapshot_id"] = str(snapshot_id)
    resp = await client.post("/sandbox/sandboxes", json=payload, headers=headers)
    assert resp.status_code == 201, resp.text
    return dict(resp.json())


async def _wait_for_active(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str
) -> None:
    """Poll until the sandbox status is ``active`` or timeout."""
    deadline = asyncio.get_running_loop().time() + _POLL_TIMEOUT
    while asyncio.get_running_loop().time() < deadline:
        resp = await client.get(f"/sandbox/sandboxes/{sandbox_id}", headers=headers)
        assert resp.status_code == 200, resp.text
        status = resp.json()["status"]
        if status == "active":
            return
        if status == "error":
            raise RuntimeError(
                f"sandbox {sandbox_id} entered error state: {resp.json().get('status_detail')}"
            )
        await asyncio.sleep(_POLL_INTERVAL)
    raise TimeoutError(f"sandbox {sandbox_id} did not become active within {_POLL_TIMEOUT}s")


async def _probe_conversations(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str
) -> None:
    """Hit the agent-server conversations endpoint inside the sandbox container.

    Retries with backoff because the agent server process inside a
    freshly-started container is not immediately ready to accept connections,
    even though Docker already reports the container as ``running``.
    """
    resp = await client.get(f"/sandbox/sandboxes/{sandbox_id}", headers=headers)
    assert resp.status_code == 200, resp.text
    sandbox = resp.json()

    session_api_key = sandbox.get("session_api_key")
    assert session_api_key, (
        f"sandbox {sandbox_id} has no session_api_key (status={sandbox['status']})"
    )

    agent_url = _agent_server_url(sandbox)
    assert agent_url, (
        f"sandbox {sandbox_id} has no agent_server exposed URL "
        f"(exposed_urls={sandbox.get('exposed_urls')})"
    )

    last_exc: Exception | None = None
    for _ in range(_PROBE_RETRIES):
        try:
            conv_resp = await client.get(
                f"{agent_url}/api/conversations/search",
                headers={"X-Session-API-Key": session_api_key},
            )
            if conv_resp.status_code == 200:
                data = conv_resp.json()
                assert "items" in data, data
                return
            last_exc = AssertionError(
                f"unexpected status {conv_resp.status_code}: {conv_resp.text[:200]}"
            )
        except httpx.HTTPError as exc:
            last_exc = exc
        await asyncio.sleep(_PROBE_INTERVAL)
    raise AssertionError(
        f"agent server at {agent_url} not ready after "
        f"{_PROBE_RETRIES * _PROBE_INTERVAL:.0f}s: {last_exc}"
    )


async def _capture_snapshot(
    client: httpx.AsyncClient,
    headers: dict[str, str],
    template_id: uuid.UUID,
    sandbox_id: str,
) -> uuid.UUID:
    resp = await client.post(
        "/sandbox/sandbox-snapshots",
        data={
            "sandbox_template_id": str(template_id),
            "sandbox_id": sandbox_id,
        },
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    return uuid.UUID(resp.json()["id"])


async def _delete_sandbox(
    client: httpx.AsyncClient, headers: dict[str, str], sandbox_id: str
) -> None:
    resp = await client.delete(f"/sandbox/sandboxes/{sandbox_id}", headers=headers)
    assert resp.status_code == 204, resp.text


async def _delete_snapshot(
    client: httpx.AsyncClient, headers: dict[str, str], snapshot_id: uuid.UUID
) -> None:
    resp = await client.delete(f"/sandbox/sandbox-snapshots/{snapshot_id}", headers=headers)
    assert resp.status_code == 204, resp.text


def _agent_server_url(sandbox: dict[str, Any]) -> str | None:
    for url in sandbox.get("exposed_urls") or []:
        if url.get("name") == "agent_server":
            return str(url["url"]).rstrip("/")
    return None


def _extract_cookie(set_cookie: str, name: str) -> str | None:
    for part in set_cookie.split(";"):
        part = part.strip()
        if part.startswith(f"{name}="):
            return part[len(name) + 1 :]
    return None
