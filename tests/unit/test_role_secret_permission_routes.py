"""Route tests for the role-secret-permission grant feature (DB-backed, ASGI client)."""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.role.role_models import Role
from openhands.ev2.secret.secret_models import Secret
from openhands.ev2.user.user_models import User


async def _seed_role_secret(session: AsyncSession, *, n: int = 0) -> tuple[Role, Secret]:
    user = User(email=f"rsp{n}@example.com", username=f"rspu{n}")
    role = Role(name=f"rsp-role-{n}-{uuid.uuid4().hex[:4]}")
    session.add(user)
    session.add(role)
    await session.flush()
    secret = Secret(code=f"RSP_{n}_{uuid.uuid4().hex[:6]}", value="v", user_id=user.id)
    session.add(secret)
    await session.flush()
    return role, secret


async def _create_grant(client: AsyncClient, role_id: str, secret_id: str, **flags) -> dict:
    payload: dict = {"role_id": role_id, "secret_id": secret_id}
    payload.update(flags)
    resp = await client.post("/role-secret-permissions", json=payload)
    assert resp.status_code == 201, resp.text
    return resp.json()


class TestRoleSecretPermissionCrud:
    async def test_create_and_get(self, client: AsyncClient, session: AsyncSession) -> None:
        role, secret = await _seed_role_secret(session)
        await session.commit()
        grant = await _create_grant(client, str(role.id), str(secret.id), read_enabled=True)
        assert grant["read_enabled"] is True
        got = await client.get(f"/role-secret-permissions/{grant['id']}")
        assert got.status_code == 200
        assert got.json()["id"] == grant["id"]

    async def test_get_missing_returns_404(self, client: AsyncClient) -> None:
        assert (await client.get(f"/role-secret-permissions/{uuid.uuid4()}")).status_code == 404

    async def test_update(self, client: AsyncClient, session: AsyncSession) -> None:
        role, secret = await _seed_role_secret(session)
        await session.commit()
        grant = await _create_grant(client, str(role.id), str(secret.id))
        resp = await client.patch(
            f"/role-secret-permissions/{grant['id']}",
            json={"read_enabled": True, "delete_enabled": True},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["read_enabled"] is True
        assert body["delete_enabled"] is True

    async def test_update_missing_returns_404(self, client: AsyncClient) -> None:
        resp = await client.patch(
            f"/role-secret-permissions/{uuid.uuid4()}", json={"read_enabled": True}
        )
        assert resp.status_code == 404

    async def test_delete(self, client: AsyncClient, session: AsyncSession) -> None:
        role, secret = await _seed_role_secret(session)
        await session.commit()
        grant = await _create_grant(client, str(role.id), str(secret.id))
        assert (await client.delete(f"/role-secret-permissions/{grant['id']}")).status_code == 204
        assert (await client.get(f"/role-secret-permissions/{grant['id']}")).status_code == 404

    async def test_delete_missing_returns_404(self, client: AsyncClient) -> None:
        assert (await client.delete(f"/role-secret-permissions/{uuid.uuid4()}")).status_code == 404


class TestRoleSecretPermissionSearch:
    async def test_search_and_count(self, client: AsyncClient, session: AsyncSession) -> None:
        role, secret = await _seed_role_secret(session)
        await session.commit()
        await _create_grant(client, str(role.id), str(secret.id))
        listed = await client.get("/role-secret-permissions")
        assert listed.status_code == 200
        assert len(listed.json()["items"]) >= 1
        counted = await client.get("/role-secret-permissions/count")
        assert counted.json()["count"] >= 1

    async def test_search_with_filter(self, client: AsyncClient, session: AsyncSession) -> None:
        role, secret = await _seed_role_secret(session, n=1)
        await session.commit()
        await _create_grant(client, str(role.id), str(secret.id))
        resp = await client.get(f"/role-secret-permissions?role_id__eq={role.id}")
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 1
        assert items[0]["role_id"] == str(role.id)

    async def test_invalid_cursor_returns_400(self, client: AsyncClient) -> None:
        resp = await client.get("/role-secret-permissions?cursor=not-a-uuid")
        assert resp.status_code == 400


class TestRoleSecretPermissionBatch:
    async def test_batch_read(self, client: AsyncClient, session: AsyncSession) -> None:
        role, secret = await _seed_role_secret(session)
        await session.commit()
        g1 = await _create_grant(client, str(role.id), str(secret.id))
        missing = str(uuid.uuid4())
        resp = await client.get(f"/role-secret-permissions/batch?ids={g1['id']}&ids={missing}")
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert items[0]["id"] == g1["id"]
        assert items[1] is None

    async def test_batch_read_empty(self, client: AsyncClient) -> None:
        resp = await client.get("/role-secret-permissions/batch")
        assert resp.status_code == 200
        assert resp.json()["items"] == []

    async def test_batch_read_too_many(self, client: AsyncClient) -> None:
        ids = "&".join(f"ids={uuid.uuid4()}" for _ in range(101))
        resp = await client.get(f"/role-secret-permissions/batch?{ids}")
        assert resp.status_code == 422

    async def test_batch_write_mix(self, client: AsyncClient, session: AsyncSession) -> None:
        role, secret = await _seed_role_secret(session)
        role2, secret2 = await _seed_role_secret(session, n=1)
        await session.commit()
        g1 = await _create_grant(client, str(role.id), str(secret.id))
        resp = await client.post(
            "/role-secret-permissions/batch",
            json={
                "operations": [
                    {
                        "op": "create",
                        "data": {
                            "role_id": str(role2.id),
                            "secret_id": str(secret2.id),
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
        role, secret = await _seed_role_secret(session)
        await session.commit()
        g1 = await _create_grant(client, str(role.id), str(secret.id))
        before = (await client.get("/role-secret-permissions/count")).json()["count"]
        resp = await client.post(
            "/role-secret-permissions/batch",
            json={
                "operations": [
                    {"op": "update", "id": g1["id"], "data": {"read_enabled": True}},
                    {"op": "delete", "id": str(uuid.uuid4())},
                ]
            },
        )
        assert resp.status_code == 404
        after = (await client.get("/role-secret-permissions/count")).json()["count"]
        assert after == before

    async def test_batch_empty_ops_rejected(self, client: AsyncClient) -> None:
        resp = await client.post("/role-secret-permissions/batch", json={"operations": []})
        assert resp.status_code == 422

    async def test_batch_conflict_rolls_back(
        self, client: AsyncClient, session: AsyncSession
    ) -> None:
        role, secret = await _seed_role_secret(session)
        await session.commit()
        g1 = await _create_grant(client, str(role.id), str(secret.id))
        resp = await client.post(
            "/role-secret-permissions/batch",
            json={
                "operations": [
                    {"op": "update", "id": g1["id"], "data": {"read_enabled": True}},
                    {
                        "op": "create",
                        "data": {"role_id": str(role.id), "secret_id": str(secret.id)},
                    },
                ]
            },
        )
        assert resp.status_code == 409

    async def test_batch_orphan_returns_404(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/role-secret-permissions/batch",
            json={
                "operations": [
                    {
                        "op": "create",
                        "data": {
                            "role_id": str(uuid.uuid4()),
                            "secret_id": str(uuid.uuid4()),
                        },
                    }
                ]
            },
        )
        assert resp.status_code == 404

    async def test_batch_unknown_op_rejected(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/role-secret-permissions/batch",
            json={
                "operations": [
                    {
                        "op": "upsert",
                        "data": {"role_id": str(uuid.uuid4()), "secret_id": str(uuid.uuid4())},
                    }
                ]
            },
        )
        assert resp.status_code == 422


class TestRoleSecretPermissionCreateErrors:
    async def test_create_duplicate_returns_409(
        self, client: AsyncClient, session: AsyncSession
    ) -> None:
        role, secret = await _seed_role_secret(session)
        await session.commit()
        await _create_grant(client, str(role.id), str(secret.id))
        resp = await client.post(
            "/role-secret-permissions",
            json={"role_id": str(role.id), "secret_id": str(secret.id)},
        )
        assert resp.status_code == 409

    async def test_create_orphan_returns_404(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/role-secret-permissions",
            json={"role_id": str(uuid.uuid4()), "secret_id": str(uuid.uuid4())},
        )
        assert resp.status_code == 404
