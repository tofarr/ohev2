"""Route tests for the sandbox role-sandbox-template-permission grant feature.

The default ``client`` fixture is the seeded admin principal whose role
carries ``Permitted()`` on every entity column, including
``sandbox_template_grant_permission``, so it has full CRUD on the grant
table. sandbox templates are provider-owned (not DB rows), so the
``sandbox_template_id`` column is a free UUID with no foreign key — tests
mint random ids directly rather than seeding a template row.
"""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.role.role_models import Role

_GRANT_PATH = "/sandbox/role-sandbox-template-permissions"


async def _seed_role(session: AsyncSession, *, n: int = 0) -> Role:
    role = Role(name=f"v2-grant-role-{n}-{uuid.uuid4().hex[:4]}")
    session.add(role)
    await session.flush()
    return role


def _template_id() -> str:
    return str(uuid.uuid4())


async def _create_grant(client: AsyncClient, role_id: str, template_id: str, **flags: bool) -> dict:
    payload: dict = {"role_id": role_id, "sandbox_template_id": template_id}
    payload.update(flags)
    resp = await client.post(_GRANT_PATH, json=payload)
    assert resp.status_code == 201, resp.text
    return resp.json()


class TestRoleSandboxTemplatePermissionCrud:
    async def test_create_and_get(self, client: AsyncClient, session: AsyncSession) -> None:
        role = await _seed_role(session)
        await session.commit()
        grant = await _create_grant(client, str(role.id), _template_id(), read_enabled=True)
        assert grant["read_enabled"] is True
        got = await client.get(f"{_GRANT_PATH}/{grant['id']}")
        assert got.status_code == 200
        assert got.json()["id"] == grant["id"]

    async def test_get_missing_returns_404(self, client: AsyncClient) -> None:
        assert (await client.get(f"{_GRANT_PATH}/{uuid.uuid4()}")).status_code == 404

    async def test_update(self, client: AsyncClient, session: AsyncSession) -> None:
        role = await _seed_role(session)
        await session.commit()
        grant = await _create_grant(client, str(role.id), _template_id())
        resp = await client.patch(
            f"{_GRANT_PATH}/{grant['id']}",
            json={"read_enabled": True, "delete_enabled": True},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["read_enabled"] is True
        assert body["delete_enabled"] is True

    async def test_update_missing_returns_404(self, client: AsyncClient) -> None:
        resp = await client.patch(f"{_GRANT_PATH}/{uuid.uuid4()}", json={"read_enabled": True})
        assert resp.status_code == 404

    async def test_delete(self, client: AsyncClient, session: AsyncSession) -> None:
        role = await _seed_role(session)
        await session.commit()
        grant = await _create_grant(client, str(role.id), _template_id())
        assert (await client.delete(f"{_GRANT_PATH}/{grant['id']}")).status_code == 204
        assert (await client.get(f"{_GRANT_PATH}/{grant['id']}")).status_code == 404

    async def test_delete_missing_returns_404(self, client: AsyncClient) -> None:
        assert (await client.delete(f"{_GRANT_PATH}/{uuid.uuid4()}")).status_code == 404


class TestRoleSandboxTemplatePermissionSearch:
    async def test_search_and_count(self, client: AsyncClient, session: AsyncSession) -> None:
        role = await _seed_role(session)
        await session.commit()
        await _create_grant(client, str(role.id), _template_id())
        listed = await client.get(_GRANT_PATH)
        assert listed.status_code == 200, listed.text
        assert len(listed.json()["items"]) >= 1
        counted = await client.get(f"{_GRANT_PATH}/count")
        assert counted.status_code == 200
        assert counted.json()["count"] >= 1

    async def test_search_filters_by_role_id(
        self, client: AsyncClient, session: AsyncSession
    ) -> None:
        role = await _seed_role(session)
        await session.commit()
        await _create_grant(client, str(role.id), _template_id())
        resp = await client.get(_GRANT_PATH, params={"role_id": str(role.id)})
        assert resp.status_code == 200
        assert all(item["role_id"] == str(role.id) for item in resp.json()["items"])

    async def test_invalid_cursor_returns_400(self, client: AsyncClient) -> None:
        resp = await client.get(_GRANT_PATH, params={"cursor": "not-a-uuid"})
        assert resp.status_code == 400


class TestRoleSandboxTemplatePermissionBatch:
    async def test_batch_read(self, client: AsyncClient, session: AsyncSession) -> None:
        role = await _seed_role(session)
        await session.commit()
        grant = await _create_grant(client, str(role.id), _template_id())
        resp = await client.get(f"{_GRANT_PATH}/batch", params={"ids": grant["id"]})
        assert resp.status_code == 200, resp.text
        items = resp.json()["items"]
        assert len(items) == 1
        assert items[0]["id"] == grant["id"]

    async def test_batch_read_rejects_over_100_ids(self, client: AsyncClient) -> None:
        ids = [str(uuid.uuid4()) for _ in range(101)]
        resp = await client.get(f"{_GRANT_PATH}/batch", params={"ids": ids})
        assert resp.status_code == 422

    async def test_batch_write_create_update_delete(
        self, client: AsyncClient, session: AsyncSession
    ) -> None:
        role = await _seed_role(session)
        await session.commit()
        grant = await _create_grant(client, str(role.id), _template_id())
        ops = [
            {
                "op": "create",
                "data": {
                    "role_id": str(role.id),
                    "sandbox_template_id": _template_id(),
                    "read_enabled": True,
                },
            },
            {"op": "update", "id": grant["id"], "data": {"update_enabled": True}},
            {"op": "delete", "id": grant["id"]},
        ]
        resp = await client.post(f"{_GRANT_PATH}/batch", json={"operations": ops})
        assert resp.status_code == 200, resp.text
        results = resp.json()["items"]
        assert results[0]["read_enabled"] is True
        assert results[1]["update_enabled"] is True
        assert results[2] is None


class TestRoleSandboxTemplatePermissionConflict:
    async def test_duplicate_grant_returns_409(
        self, client: AsyncClient, session: AsyncSession
    ) -> None:
        role = await _seed_role(session)
        await session.commit()
        template_id = _template_id()
        await _create_grant(client, str(role.id), template_id)
        resp = await client.post(
            _GRANT_PATH,
            json={"role_id": str(role.id), "sandbox_template_id": template_id},
        )
        assert resp.status_code == 409
