"""Route tests for the sandbox grant permission features (DB-backed, ASGI client).

Covers all three routers: role-sandbox-template-permissions,
role-sandbox-permissions, and role-sandbox-snapshot-permissions.
The template router is tested exhaustively; the sandbox and snapshot routers
get representative CRUD + batch tests each.
"""

from __future__ import annotations

import uuid
from typing import Any

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.role.role_models import Role
from openhands.ev2.sandbox.sandbox_models import (
    DockerSandboxTemplateSpec,
    FuseySandboxStorageSpec,
    OpenHandsAgentServerSpec,
    Sandbox,
    SandboxFilesystem,
    SandboxFilesystemStatus,
    SandboxSnapshot,
    SandboxSnapshotStatus,
    SandboxStatus,
    SandboxTemplate,
)
from openhands.ev2.user.user_models import User

# ---------------------------------------------------------------------------
# DB seed helpers (bypass the API so we don't depend on sandbox route perms)
# ---------------------------------------------------------------------------


async def _seed_template(session: AsyncSession, *, n: int = 0) -> tuple[Role, SandboxTemplate]:
    role = Role(name=f"rt-role-{n}-{uuid.uuid4().hex[:4]}")
    user = User(email=f"rt{n}@e.com", username=f"rtu{n}")
    session.add(role)
    session.add(user)
    await session.flush()
    tpl = SandboxTemplate(
        name=f"rt-tpl-{n}-{uuid.uuid4().hex[:6]}",
        provider_kind="docker",
        template_spec=DockerSandboxTemplateSpec(image="img"),
        server_spec=OpenHandsAgentServerSpec(internal_port=18000),
        storage_spec=FuseySandboxStorageSpec(mount_path="/ws"),
        user_id=user.id,
    )
    session.add(tpl)
    await session.flush()
    return role, tpl


async def _seed_sandbox(session: AsyncSession, *, n: int = 0) -> tuple[Role, Sandbox]:
    role, tpl = await _seed_template(session, n=n)
    fs = SandboxFilesystem(
        storage_kind="fusey",
        object_prefix=f"rt-obj-{n}-{uuid.uuid4().hex[:6]}",
        user_id=tpl.user_id,
        status=SandboxFilesystemStatus.READY,
    )
    session.add(fs)
    await session.flush()
    sb = Sandbox(
        name=f"rt-sb-{n}-{uuid.uuid4().hex[:4]}",
        template_id=tpl.id,
        filesystem_id=fs.id,
        provider_kind="docker",
        user_id=tpl.user_id,
        status=SandboxStatus.INACTIVE,
    )
    session.add(sb)
    await session.flush()
    return role, sb


async def _seed_snapshot(session: AsyncSession, *, n: int = 0) -> tuple[Role, SandboxSnapshot]:
    from openhands.ev2.sandbox.sandbox_models import (
        FuseySandboxSnapshotArtifact,
        SandboxStorageKind,
    )

    role, sb = await _seed_sandbox(session, n=n)
    snap = SandboxSnapshot(
        name=f"rt-snap-{n}-{uuid.uuid4().hex[:4]}",
        filesystem_id=sb.filesystem_id,
        storage_kind=SandboxStorageKind.FUSEY,
        generation=f"gen-{n}",
        snapshot_artifact=FuseySandboxSnapshotArtifact(
            filesystem_id=sb.filesystem_id, generation=f"gen-{n}"
        ),
        user_id=sb.user_id,
        status=SandboxSnapshotStatus.READY,
    )
    session.add(snap)
    await session.flush()
    return role, snap


async def _create_template_grant(
    client: AsyncClient, role_id: str, template_id: str, **flags: Any
) -> dict:
    payload: dict = {"role_id": role_id, "sandbox_template_id": template_id}
    payload.update(flags)
    resp = await client.post("/role-sandbox-template-permissions", json=payload)
    assert resp.status_code == 201, resp.text
    return resp.json()


async def _create_sandbox_grant(
    client: AsyncClient, role_id: str, sandbox_id: str, **flags: Any
) -> dict:
    payload: dict = {"role_id": role_id, "sandbox_id": sandbox_id}
    payload.update(flags)
    resp = await client.post("/role-sandbox-permissions", json=payload)
    assert resp.status_code == 201, resp.text
    return resp.json()


async def _create_snapshot_grant(
    client: AsyncClient, role_id: str, snapshot_id: str, **flags: Any
) -> dict:
    payload: dict = {"role_id": role_id, "sandbox_snapshot_id": snapshot_id}
    payload.update(flags)
    resp = await client.post("/role-sandbox-snapshot-permissions", json=payload)
    assert resp.status_code == 201, resp.text
    return resp.json()


# ---------------------------------------------------------------------------
# Template permission routes — exhaustive
# ---------------------------------------------------------------------------


class TestTemplatePermissionCrud:
    async def test_create_and_get(self, client: AsyncClient, session: AsyncSession) -> None:
        role, tpl = await _seed_template(session)
        await session.commit()
        grant = await _create_template_grant(client, str(role.id), str(tpl.id), read_enabled=True)
        assert grant["read_enabled"] is True
        got = await client.get(f"/role-sandbox-template-permissions/{grant['id']}")
        assert got.status_code == 200
        assert got.json()["id"] == grant["id"]

    async def test_get_missing_returns_404(self, client: AsyncClient) -> None:
        resp = await client.get(f"/role-sandbox-template-permissions/{uuid.uuid4()}")
        assert resp.status_code == 404

    async def test_update(self, client: AsyncClient, session: AsyncSession) -> None:
        role, tpl = await _seed_template(session)
        await session.commit()
        grant = await _create_template_grant(client, str(role.id), str(tpl.id))
        resp = await client.patch(
            f"/role-sandbox-template-permissions/{grant['id']}",
            json={"read_enabled": True, "delete_enabled": True},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["read_enabled"] is True
        assert body["delete_enabled"] is True

    async def test_update_missing_returns_404(self, client: AsyncClient) -> None:
        resp = await client.patch(
            f"/role-sandbox-template-permissions/{uuid.uuid4()}",
            json={"read_enabled": True},
        )
        assert resp.status_code == 404

    async def test_delete(self, client: AsyncClient, session: AsyncSession) -> None:
        role, tpl = await _seed_template(session)
        await session.commit()
        grant = await _create_template_grant(client, str(role.id), str(tpl.id))
        resp = await client.delete(f"/role-sandbox-template-permissions/{grant['id']}")
        assert resp.status_code == 204
        assert (
            await client.get(f"/role-sandbox-template-permissions/{grant['id']}")
        ).status_code == 404

    async def test_delete_missing_returns_404(self, client: AsyncClient) -> None:
        resp = await client.delete(f"/role-sandbox-template-permissions/{uuid.uuid4()}")
        assert resp.status_code == 404


class TestTemplatePermissionSearch:
    async def test_search_and_count(self, client: AsyncClient, session: AsyncSession) -> None:
        role, tpl = await _seed_template(session)
        await session.commit()
        await _create_template_grant(client, str(role.id), str(tpl.id))
        listed = await client.get("/role-sandbox-template-permissions")
        assert listed.status_code == 200
        assert len(listed.json()["items"]) >= 1
        counted = await client.get("/role-sandbox-template-permissions/count")
        assert counted.json()["count"] >= 1

    async def test_search_with_filter(self, client: AsyncClient, session: AsyncSession) -> None:
        role, tpl = await _seed_template(session, n=1)
        await session.commit()
        await _create_template_grant(client, str(role.id), str(tpl.id))
        resp = await client.get(f"/role-sandbox-template-permissions?role_id__eq={role.id}")
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 1
        assert items[0]["role_id"] == str(role.id)

    async def test_invalid_cursor_returns_400(self, client: AsyncClient) -> None:
        resp = await client.get("/role-sandbox-template-permissions?cursor=not-a-uuid")
        assert resp.status_code == 400


class TestTemplatePermissionBatch:
    async def test_batch_read(self, client: AsyncClient, session: AsyncSession) -> None:
        role, tpl = await _seed_template(session)
        await session.commit()
        g1 = await _create_template_grant(client, str(role.id), str(tpl.id))
        missing = str(uuid.uuid4())
        resp = await client.get(
            f"/role-sandbox-template-permissions/batch?ids={g1['id']}&ids={missing}"
        )
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert items[0]["id"] == g1["id"]
        assert items[1] is None

    async def test_batch_read_empty(self, client: AsyncClient) -> None:
        resp = await client.get("/role-sandbox-template-permissions/batch")
        assert resp.status_code == 200
        assert resp.json()["items"] == []

    async def test_batch_read_too_many(self, client: AsyncClient) -> None:
        ids = "&".join(f"ids={uuid.uuid4()}" for _ in range(101))
        resp = await client.get(f"/role-sandbox-template-permissions/batch?{ids}")
        assert resp.status_code == 422

    async def test_batch_write_mix(self, client: AsyncClient, session: AsyncSession) -> None:
        role, tpl = await _seed_template(session)
        role2, tpl2 = await _seed_template(session, n=1)
        await session.commit()
        g1 = await _create_template_grant(client, str(role.id), str(tpl.id))
        resp = await client.post(
            "/role-sandbox-template-permissions/batch",
            json={
                "operations": [
                    {
                        "op": "create",
                        "data": {
                            "role_id": str(role2.id),
                            "sandbox_template_id": str(tpl2.id),
                            "read_enabled": True,
                        },
                    },
                    {"op": "update", "id": g1["id"], "data": {"update_enabled": True}},
                    {"op": "delete", "id": g1["id"]},
                ]
            },
        )
        assert resp.status_code == 200, resp.text
        items = resp.json()["items"]
        assert items[0]["read_enabled"] is True
        assert items[1]["update_enabled"] is True
        assert items[2] is None

    async def test_batch_write_atomic_rollback(
        self, client: AsyncClient, session: AsyncSession
    ) -> None:
        role, tpl = await _seed_template(session)
        await session.commit()
        g1 = await _create_template_grant(client, str(role.id), str(tpl.id))
        before = (await client.get("/role-sandbox-template-permissions/count")).json()["count"]
        resp = await client.post(
            "/role-sandbox-template-permissions/batch",
            json={
                "operations": [
                    {"op": "update", "id": g1["id"], "data": {"read_enabled": True}},
                    {"op": "delete", "id": str(uuid.uuid4())},
                ]
            },
        )
        assert resp.status_code == 404
        after = (await client.get("/role-sandbox-template-permissions/count")).json()["count"]
        assert after == before

    async def test_batch_empty_ops_rejected(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/role-sandbox-template-permissions/batch", json={"operations": []}
        )
        assert resp.status_code == 422

    async def test_batch_conflict_rolls_back(
        self, client: AsyncClient, session: AsyncSession
    ) -> None:
        role, tpl = await _seed_template(session)
        await session.commit()
        g1 = await _create_template_grant(client, str(role.id), str(tpl.id))
        resp = await client.post(
            "/role-sandbox-template-permissions/batch",
            json={
                "operations": [
                    {"op": "update", "id": g1["id"], "data": {"read_enabled": True}},
                    {
                        "op": "create",
                        "data": {
                            "role_id": str(role.id),
                            "sandbox_template_id": str(tpl.id),
                        },
                    },
                ]
            },
        )
        assert resp.status_code == 409

    async def test_batch_unknown_op_rejected(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/role-sandbox-template-permissions/batch",
            json={
                "operations": [
                    {
                        "op": "upsert",
                        "data": {
                            "role_id": str(uuid.uuid4()),
                            "sandbox_template_id": str(uuid.uuid4()),
                        },
                    }
                ]
            },
        )
        assert resp.status_code == 422


class TestTemplatePermissionCreateErrors:
    async def test_create_duplicate_returns_409(
        self, client: AsyncClient, session: AsyncSession
    ) -> None:
        role, tpl = await _seed_template(session)
        await session.commit()
        await _create_template_grant(client, str(role.id), str(tpl.id))
        resp = await client.post(
            "/role-sandbox-template-permissions",
            json={"role_id": str(role.id), "sandbox_template_id": str(tpl.id)},
        )
        assert resp.status_code == 409

    async def test_create_orphan_returns_404(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/role-sandbox-template-permissions",
            json={
                "role_id": str(uuid.uuid4()),
                "sandbox_template_id": str(uuid.uuid4()),
            },
        )
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Sandbox (resource) permission routes — representative
# ---------------------------------------------------------------------------


class TestSandboxPermissionRoutes:
    async def test_create_and_get(self, client: AsyncClient, session: AsyncSession) -> None:
        role, sb = await _seed_sandbox(session)
        await session.commit()
        grant = await _create_sandbox_grant(client, str(role.id), str(sb.id), read_enabled=True)
        assert grant["read_enabled"] is True
        got = await client.get(f"/role-sandbox-permissions/{grant['id']}")
        assert got.status_code == 200

    async def test_get_missing_returns_404(self, client: AsyncClient) -> None:
        resp = await client.get(f"/role-sandbox-permissions/{uuid.uuid4()}")
        assert resp.status_code == 404

    async def test_update(self, client: AsyncClient, session: AsyncSession) -> None:
        role, sb = await _seed_sandbox(session)
        await session.commit()
        grant = await _create_sandbox_grant(client, str(role.id), str(sb.id))
        resp = await client.patch(
            f"/role-sandbox-permissions/{grant['id']}",
            json={"update_enabled": True},
        )
        assert resp.status_code == 200
        assert resp.json()["update_enabled"] is True

    async def test_delete(self, client: AsyncClient, session: AsyncSession) -> None:
        role, sb = await _seed_sandbox(session)
        await session.commit()
        grant = await _create_sandbox_grant(client, str(role.id), str(sb.id))
        resp = await client.delete(f"/role-sandbox-permissions/{grant['id']}")
        assert resp.status_code == 204

    async def test_search_and_count(self, client: AsyncClient, session: AsyncSession) -> None:
        role, sb = await _seed_sandbox(session)
        await session.commit()
        await _create_sandbox_grant(client, str(role.id), str(sb.id))
        listed = await client.get("/role-sandbox-permissions")
        assert listed.status_code == 200
        assert len(listed.json()["items"]) >= 1
        counted = await client.get("/role-sandbox-permissions/count")
        assert counted.json()["count"] >= 1

    async def test_batch_read(self, client: AsyncClient, session: AsyncSession) -> None:
        role, sb = await _seed_sandbox(session)
        await session.commit()
        g1 = await _create_sandbox_grant(client, str(role.id), str(sb.id))
        resp = await client.get(
            f"/role-sandbox-permissions/batch?ids={g1['id']}&ids={uuid.uuid4()}"
        )
        assert resp.status_code == 200
        assert resp.json()["items"][0]["id"] == g1["id"]
        assert resp.json()["items"][1] is None

    async def test_batch_write(self, client: AsyncClient, session: AsyncSession) -> None:
        role, sb = await _seed_sandbox(session)
        role2, sb2 = await _seed_sandbox(session, n=1)
        await session.commit()
        g1 = await _create_sandbox_grant(client, str(role.id), str(sb.id))
        resp = await client.post(
            "/role-sandbox-permissions/batch",
            json={
                "operations": [
                    {
                        "op": "create",
                        "data": {
                            "role_id": str(role2.id),
                            "sandbox_id": str(sb2.id),
                            "read_enabled": True,
                        },
                    },
                    {"op": "update", "id": g1["id"], "data": {"delete_enabled": True}},
                ]
            },
        )
        assert resp.status_code == 200, resp.text
        items = resp.json()["items"]
        assert items[0]["read_enabled"] is True
        assert items[1]["delete_enabled"] is True

    async def test_create_duplicate_returns_409(
        self, client: AsyncClient, session: AsyncSession
    ) -> None:
        role, sb = await _seed_sandbox(session)
        await session.commit()
        await _create_sandbox_grant(client, str(role.id), str(sb.id))
        resp = await client.post(
            "/role-sandbox-permissions",
            json={"role_id": str(role.id), "sandbox_id": str(sb.id)},
        )
        assert resp.status_code == 409

    async def test_invalid_cursor_returns_400(self, client: AsyncClient) -> None:
        resp = await client.get("/role-sandbox-permissions?cursor=bad")
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Snapshot permission routes — representative
# ---------------------------------------------------------------------------


class TestSnapshotPermissionRoutes:
    async def test_create_and_get(self, client: AsyncClient, session: AsyncSession) -> None:
        role, snap = await _seed_snapshot(session)
        await session.commit()
        grant = await _create_snapshot_grant(
            client, str(role.id), str(snap.id), delete_enabled=True
        )
        assert grant["delete_enabled"] is True
        got = await client.get(f"/role-sandbox-snapshot-permissions/{grant['id']}")
        assert got.status_code == 200

    async def test_get_missing_returns_404(self, client: AsyncClient) -> None:
        resp = await client.get(f"/role-sandbox-snapshot-permissions/{uuid.uuid4()}")
        assert resp.status_code == 404

    async def test_update(self, client: AsyncClient, session: AsyncSession) -> None:
        role, snap = await _seed_snapshot(session)
        await session.commit()
        grant = await _create_snapshot_grant(client, str(role.id), str(snap.id))
        resp = await client.patch(
            f"/role-sandbox-snapshot-permissions/{grant['id']}",
            json={"read_enabled": True},
        )
        assert resp.status_code == 200
        assert resp.json()["read_enabled"] is True

    async def test_delete(self, client: AsyncClient, session: AsyncSession) -> None:
        role, snap = await _seed_snapshot(session)
        await session.commit()
        grant = await _create_snapshot_grant(client, str(role.id), str(snap.id))
        resp = await client.delete(f"/role-sandbox-snapshot-permissions/{grant['id']}")
        assert resp.status_code == 204

    async def test_search_and_count(self, client: AsyncClient, session: AsyncSession) -> None:
        role, snap = await _seed_snapshot(session)
        await session.commit()
        await _create_snapshot_grant(client, str(role.id), str(snap.id))
        listed = await client.get("/role-sandbox-snapshot-permissions")
        assert listed.status_code == 200
        assert len(listed.json()["items"]) >= 1
        counted = await client.get("/role-sandbox-snapshot-permissions/count")
        assert counted.json()["count"] >= 1

    async def test_batch_read(self, client: AsyncClient, session: AsyncSession) -> None:
        role, snap = await _seed_snapshot(session)
        await session.commit()
        g1 = await _create_snapshot_grant(client, str(role.id), str(snap.id))
        resp = await client.get(
            f"/role-sandbox-snapshot-permissions/batch?ids={g1['id']}&ids={uuid.uuid4()}"
        )
        assert resp.status_code == 200
        assert resp.json()["items"][0]["id"] == g1["id"]
        assert resp.json()["items"][1] is None

    async def test_batch_write(self, client: AsyncClient, session: AsyncSession) -> None:
        role, snap = await _seed_snapshot(session)
        role2, snap2 = await _seed_snapshot(session, n=1)
        await session.commit()
        g1 = await _create_snapshot_grant(client, str(role.id), str(snap.id))
        resp = await client.post(
            "/role-sandbox-snapshot-permissions/batch",
            json={
                "operations": [
                    {
                        "op": "create",
                        "data": {
                            "role_id": str(role2.id),
                            "sandbox_snapshot_id": str(snap2.id),
                            "read_enabled": True,
                        },
                    },
                    {"op": "update", "id": g1["id"], "data": {"update_enabled": True}},
                ]
            },
        )
        assert resp.status_code == 200, resp.text
        items = resp.json()["items"]
        assert items[0]["read_enabled"] is True
        assert items[1]["update_enabled"] is True

    async def test_create_duplicate_returns_409(
        self, client: AsyncClient, session: AsyncSession
    ) -> None:
        role, snap = await _seed_snapshot(session)
        await session.commit()
        await _create_snapshot_grant(client, str(role.id), str(snap.id))
        resp = await client.post(
            "/role-sandbox-snapshot-permissions",
            json={"role_id": str(role.id), "sandbox_snapshot_id": str(snap.id)},
        )
        assert resp.status_code == 409

    async def test_invalid_cursor_returns_400(self, client: AsyncClient) -> None:
        resp = await client.get("/role-sandbox-snapshot-permissions?cursor=bad")
        assert resp.status_code == 400
