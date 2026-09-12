"""Route tests for the DB-backed ``/sandbox/sandbox-configs`` REST surface."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.auth.auth_models import ApiKey
from openhands.ev2.auth.auth_tokens import InvalidTokenError, TokenService
from openhands.ev2.encryption.encryption_service import get_encryption_service
from openhands.ev2.role.role_models import Role
from openhands.ev2.sandbox.sandbox_config_models import SandboxConfig


async def _create_template(client: AsyncClient) -> str:
    resp = await client.post(
        "/sandbox/sandbox-templates",
        json={"docker_image_tag": f"img-{uuid.uuid4()}"},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


async def _config_row(session: AsyncSession, config_id: str) -> SandboxConfig:
    row = await session.scalar(
        select(SandboxConfig).where(SandboxConfig.id == uuid.UUID(config_id))
    )
    assert row is not None, "sandbox config row missing"
    return row


class TestSandboxConfigRoutes:
    async def test_crud_lifecycle(self, client: AsyncClient) -> None:
        template_id = await _create_template(client)

        created = await client.post(
            "/sandbox/sandbox-configs",
            json={"sandbox_template_id": template_id, "enabled": True},
        )
        assert created.status_code == 201, created.text
        config = created.json()
        config_id = config["id"]
        assert config["enabled"] is True
        assert "session_api_key" not in config

        got = await client.get(f"/sandbox/sandbox-configs/{config_id}")
        assert got.status_code == 200
        assert got.json()["id"] == config_id

        patched = await client.patch(
            f"/sandbox/sandbox-configs/{config_id}",
            json={"enabled": False},
        )
        assert patched.status_code == 200, patched.text
        assert patched.json()["enabled"] is False

        deleted = await client.delete(f"/sandbox/sandbox-configs/{config_id}")
        assert deleted.status_code == 204

        missing = await client.get(f"/sandbox/sandbox-configs/{config_id}")
        assert missing.status_code == 404

    async def test_search_and_count(self, client: AsyncClient) -> None:
        template_id = await _create_template(client)
        for _ in range(3):
            resp = await client.post(
                "/sandbox/sandbox-configs",
                json={"sandbox_template_id": template_id},
            )
            assert resp.status_code == 201

        search = await client.get(
            "/sandbox/sandbox-configs",
            params={"sandbox_template_id__eq": template_id, "limit": 2},
        )
        assert search.status_code == 200
        assert len(search.json()["items"]) == 2
        assert search.json()["next_cursor"] is not None

        count = await client.get(
            "/sandbox/sandbox-configs/count",
            params={"sandbox_template_id__eq": template_id},
        )
        assert count.status_code == 200
        assert count.json()["count"] == 3

    async def test_batch_read(self, client: AsyncClient) -> None:
        template_id = await _create_template(client)
        ids = []
        for _ in range(2):
            resp = await client.post(
                "/sandbox/sandbox-configs",
                json={"sandbox_template_id": template_id},
            )
            assert resp.status_code == 201
            ids.append(resp.json()["id"])

        batch = await client.get("/sandbox/sandbox-configs/batch", params={"ids": ids})
        assert batch.status_code == 200
        assert len(batch.json()["items"]) == 2

    async def test_batch_write(self, client: AsyncClient) -> None:
        template_id = await _create_template(client)
        batch_resp = await client.post(
            "/sandbox/sandbox-configs/batch",
            json={
                "operations": [
                    {"op": "create", "data": {"sandbox_template_id": template_id}},
                    {"op": "create", "data": {"sandbox_template_id": template_id}},
                ]
            },
        )
        assert batch_resp.status_code == 200, batch_resp.text
        items = batch_resp.json()["items"]
        assert len(items) == 2
        created_id = items[0]["id"]

        update_batch = await client.post(
            "/sandbox/sandbox-configs/batch",
            json={
                "operations": [
                    {"op": "update", "id": created_id, "data": {"enabled": True}},
                    {"op": "delete", "id": items[1]["id"]},
                ]
            },
        )
        assert update_batch.status_code == 200
        assert update_batch.json()["items"][0]["enabled"] is True
        assert update_batch.json()["items"][1] is None

    async def test_invalid_template_returns_404(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/sandbox/sandbox-configs",
            json={"sandbox_template_id": str(uuid.uuid4())},
        )
        assert resp.status_code == 404

    async def test_snapshot_on_deactivate_defaults_from_template(self, client: AsyncClient) -> None:
        template_resp = await client.post(
            "/sandbox/sandbox-templates",
            json={"docker_image_tag": f"snap-{uuid.uuid4()}", "snapshot_on_deactivate": True},
        )
        assert template_resp.status_code == 201
        template_id = template_resp.json()["id"]

        config_resp = await client.post(
            "/sandbox/sandbox-configs",
            json={"sandbox_template_id": template_id},
        )
        assert config_resp.status_code == 201
        assert config_resp.json()["snapshot_on_deactivate"] is True

    async def test_expires_at_set(self, client: AsyncClient) -> None:
        template_id = await _create_template(client)
        expiry = datetime(2030, 1, 1, tzinfo=UTC)
        resp = await client.post(
            "/sandbox/sandbox-configs",
            json={
                "sandbox_template_id": template_id,
                "expires_at": expiry.isoformat(),
            },
        )
        assert resp.status_code == 201, resp.text
        assert resp.json()["expires_at"] is not None

    async def test_get_missing_returns_404(self, client: AsyncClient) -> None:
        resp = await client.get(f"/sandbox/sandbox-configs/{uuid.uuid4()}")
        assert resp.status_code == 404

    async def test_patch_missing_returns_404(self, client: AsyncClient) -> None:
        resp = await client.patch(
            f"/sandbox/sandbox-configs/{uuid.uuid4()}",
            json={"enabled": False},
        )
        assert resp.status_code == 404

    async def test_delete_missing_returns_404(self, client: AsyncClient) -> None:
        resp = await client.delete(f"/sandbox/sandbox-configs/{uuid.uuid4()}")
        assert resp.status_code == 404

    async def test_batch_read_too_many_returns_422(self, client: AsyncClient) -> None:
        ids = [str(uuid.uuid4()) for _ in range(101)]
        resp = await client.get("/sandbox/sandbox-configs/batch", params={"ids": ids})
        assert resp.status_code == 422

    async def test_batch_write_empty_ops_rejected(self, client: AsyncClient) -> None:
        resp = await client.post("/sandbox/sandbox-configs/batch", json={"operations": []})
        assert resp.status_code == 422

    async def test_invalid_cursor_returns_400(self, client: AsyncClient) -> None:
        resp = await client.get("/sandbox/sandbox-configs", params={"cursor": "not-a-uuid"})
        assert resp.status_code == 400

    async def test_batch_read_empty(self, client: AsyncClient) -> None:
        resp = await client.get("/sandbox/sandbox-configs/batch")
        assert resp.status_code == 200
        assert resp.json()["items"] == []

    async def test_batch_write_delete_missing_maps_to_404(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/sandbox/sandbox-configs/batch",
            json={"operations": [{"op": "delete", "id": str(uuid.uuid4())}]},
        )
        assert resp.status_code == 404

    async def test_batch_write_update_missing_maps_to_404(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/sandbox/sandbox-configs/batch",
            json={
                "operations": [{"op": "update", "id": str(uuid.uuid4()), "data": {"enabled": True}}]
            },
        )
        assert resp.status_code == 404


class TestSandboxConfigSessionApiKey:
    """The session key is a real ApiKey row minted via the api_key service."""

    async def test_create_mints_system_api_key(
        self, client: AsyncClient, session: AsyncSession
    ) -> None:
        template_id = await _create_template(client)
        expires = datetime.now(UTC) + timedelta(hours=2)
        resp = await client.post(
            "/sandbox/sandbox-configs",
            json={
                "sandbox_template_id": template_id,
                "expires_at": expires.isoformat(),
            },
        )
        assert resp.status_code == 201, resp.text
        config_id = resp.json()["id"]

        row = await _config_row(session, config_id)
        assert row.session_api_key_id is not None
        key = await session.get(ApiKey, row.session_api_key_id)
        assert key is not None, "session API key row missing"
        assert key.name == f"Sandbox {config_id} API key"
        assert key.system is True
        assert key.enabled is True
        assert key.expires_at is not None
        # The raw key (decrypted from the config) authenticates as the creator.
        raw = get_encryption_service().decrypt_value(row.session_api_key)
        auth = await TokenService(session).authenticate(raw)
        assert auth.user_id == row.creator_id
        assert auth.enabled is True

    async def test_create_links_restricting_role_when_seeded(
        self, client: AsyncClient, session: AsyncSession
    ) -> None:
        role = Role(name="API key")
        session.add(role)
        await session.commit()

        template_id = await _create_template(client)
        resp = await client.post(
            "/sandbox/sandbox-configs",
            json={"sandbox_template_id": template_id},
        )
        assert resp.status_code == 201, resp.text

        row = await _config_row(session, resp.json()["id"])
        assert row.session_api_key_id is not None
        key = await session.get(ApiKey, row.session_api_key_id)
        assert key is not None
        assert key.role_id == role.id

    async def test_patch_expires_at_syncs_key_expiry(
        self, client: AsyncClient, session: AsyncSession
    ) -> None:
        template_id = await _create_template(client)
        resp = await client.post(
            "/sandbox/sandbox-configs",
            json={"sandbox_template_id": template_id},
        )
        assert resp.status_code == 201, resp.text
        config_id = resp.json()["id"]

        new_expiry = datetime.now(UTC) + timedelta(hours=6)
        patched = await client.patch(
            f"/sandbox/sandbox-configs/{config_id}",
            json={"expires_at": new_expiry.isoformat()},
        )
        assert patched.status_code == 200, patched.text

        row = await _config_row(session, config_id)
        key = await session.get(ApiKey, row.session_api_key_id)
        assert key is not None
        assert key.expires_at == datetime.fromisoformat(patched.json()["expires_at"])

    async def test_patch_expires_at_after_key_reaped(
        self, client: AsyncClient, session: AsyncSession
    ) -> None:
        # When the cleanup sweep reaps the key row, the FK SET NULLs the link;
        # patching expiry then has no key to sync and must still succeed.
        template_id = await _create_template(client)
        resp = await client.post(
            "/sandbox/sandbox-configs",
            json={"sandbox_template_id": template_id},
        )
        assert resp.status_code == 201, resp.text
        config_id = resp.json()["id"]

        row = await _config_row(session, config_id)
        key = await session.get(ApiKey, row.session_api_key_id)
        assert key is not None
        await session.delete(key)
        await session.commit()

        new_expiry = datetime.now(UTC) + timedelta(hours=3)
        patched = await client.patch(
            f"/sandbox/sandbox-configs/{config_id}",
            json={"expires_at": new_expiry.isoformat()},
        )
        assert patched.status_code == 200, patched.text
        row = await _config_row(session, config_id)
        await session.refresh(row)  # DB-side FK SET NULL is not in the identity map
        assert row.session_api_key_id is None

    async def test_delete_config_revokes_session_key(
        self, client: AsyncClient, session: AsyncSession
    ) -> None:
        template_id = await _create_template(client)
        resp = await client.post(
            "/sandbox/sandbox-configs",
            json={"sandbox_template_id": template_id},
        )
        assert resp.status_code == 201, resp.text
        config_id = resp.json()["id"]

        row = await _config_row(session, config_id)
        key_id = row.session_api_key_id
        raw = get_encryption_service().decrypt_value(row.session_api_key)

        deleted = await client.delete(f"/sandbox/sandbox-configs/{config_id}")
        assert deleted.status_code == 204
        assert await session.get(ApiKey, key_id) is None
        # The raw key no longer authenticates.
        with pytest.raises(InvalidTokenError):
            await TokenService(session).authenticate(raw)
