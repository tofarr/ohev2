"""Route tests for the role feature (DB-backed, via ASGI client)."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from tests.unit._auth_helpers import assign_role as _assign_role
from tests.unit._auth_helpers import make_principal as _make_principal

from openhands.ev2.security.security_models import Permitted, ReadOnly
from openhands.ev2.util.auth_token import create_auth_token


class TestCreateRoleRoute:
    async def test_create_role(self, client: AsyncClient) -> None:
        resp = await client.post("/roles", json={"name": "admin"})
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["name"] == "admin"
        assert uuid.UUID(body["id"])
        assert body["created_at"] is not None

    async def test_create_role_with_entity_permissions(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/roles",
            json={
                "name": "admin",
                "user_permission": {"kind": "Permitted"},
                "role_permission": {"kind": "ReadOnly"},
            },
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["user_permission"]["kind"] == "Permitted"
        assert body["role_permission"]["kind"] == "ReadOnly"

    async def test_create_role_with_single_permission(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/roles",
            json={"name": "viewer", "user_permission": {"kind": "ReadOnly"}},
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["user_permission"]["kind"] == "ReadOnly"

    async def test_create_duplicate_name_returns_409(self, client: AsyncClient) -> None:
        await client.post("/roles", json={"name": "dup"})
        resp2 = await client.post("/roles", json={"name": "dup"})
        assert resp2.status_code == 409

    async def test_create_invalid_name_returns_422(self, client: AsyncClient) -> None:
        resp = await client.post("/roles", json={"name": ""})
        assert resp.status_code == 422


class TestGetRoleRoute:
    async def test_get_existing_role(self, client: AsyncClient) -> None:
        create = await client.post("/roles", json={"name": "viewer"})
        rid = create.json()["id"]
        resp = await client.get(f"/roles/{rid}")
        assert resp.status_code == 200
        assert resp.json()["name"] == "viewer"

    async def test_get_missing_role_returns_404(self, client: AsyncClient) -> None:
        resp = await client.get(f"/roles/{uuid.uuid4()}")
        assert resp.status_code == 404

    async def test_get_invalid_uuid_returns_422(self, client: AsyncClient) -> None:
        resp = await client.get("/roles/not-a-uuid")
        assert resp.status_code == 422


class TestListRolesRoute:
    async def test_search_empty(self, client: AsyncClient) -> None:
        resp = await client.get("/roles")
        assert resp.status_code == 200
        body = resp.json()
        # The conftest seeds a test-admin role.
        names = {r["name"] for r in body["items"]}
        assert "test-admin" in names
        assert body["next_cursor"] is None
        assert body["limit"] == 50

    async def test_search_with_limit(self, client: AsyncClient) -> None:
        for i in range(3):
            await client.post("/roles", json={"name": f"r{i}"})
        resp = await client.get("/roles?limit=2")
        body = resp.json()
        assert len(body["items"]) == 2
        assert body["next_cursor"] is not None
        assert body["limit"] == 2

    async def test_search_pagination(self, client: AsyncClient) -> None:
        for i in range(4):
            await client.post("/roles", json={"name": f"p{i}"})
        resp1 = await client.get("/roles?limit=2")
        cursor = resp1.json()["next_cursor"]
        assert cursor is not None
        resp2 = await client.get(f"/roles?limit=2&cursor={cursor}")
        assert resp2.status_code == 200
        assert len(resp2.json()["items"]) == 2

    async def test_search_invalid_cursor_returns_400(self, client: AsyncClient) -> None:
        resp = await client.get("/roles?cursor=not-a-uuid")
        assert resp.status_code == 400

    async def test_search_limit_out_of_range_returns_422(self, client: AsyncClient) -> None:
        assert (await client.get("/roles?limit=0")).status_code == 422
        assert (await client.get("/roles?limit=101")).status_code == 422

    async def test_search_name_contains_filter(self, client: AsyncClient) -> None:
        await client.post("/roles", json={"name": "Admin"})
        await client.post("/roles", json={"name": "viewer"})
        resp = await client.get("/roles?name__contains=ADMIN")
        assert resp.status_code == 200
        names = {r["name"] for r in resp.json()["items"]}
        assert "Admin" in names
        assert "viewer" not in names

    async def test_search_name_eq_filter(self, client: AsyncClient) -> None:
        await client.post("/roles", json={"name": "admin"})
        await client.post("/roles", json={"name": "viewer"})
        resp = await client.get("/roles?name__eq=admin")
        assert resp.status_code == 200
        names = {r["name"] for r in resp.json()["items"]}
        assert names == {"admin"}


class TestCountRolesRoute:
    async def test_count_empty(self, client: AsyncClient) -> None:
        resp = await client.get("/roles/count")
        assert resp.status_code == 200
        # The conftest seeds a test-admin role.
        assert resp.json()["count"] == 1

    async def test_count_after_creates(self, client: AsyncClient) -> None:
        for i in range(3):
            await client.post("/roles", json={"name": f"c{i}"})
        resp = await client.get("/roles/count")
        assert resp.status_code == 200
        # 3 created + 1 seeded test-admin.
        assert resp.json()["count"] == 4

    async def test_count_with_name_filter(self, client: AsyncClient) -> None:
        await client.post("/roles", json={"name": "admin"})
        await client.post("/roles", json={"name": "viewer"})
        resp = await client.get("/roles/count?name__contains=admin")
        assert resp.status_code == 200
        # "admin" matches the created role + the seeded "test-admin" role.
        assert resp.json()["count"] == 2


class TestUpdateRoleRoute:
    async def test_update_name(self, client: AsyncClient) -> None:
        create = await client.post("/roles", json={"name": "old"})
        rid = create.json()["id"]
        resp = await client.patch(f"/roles/{rid}", json={"name": "new"})
        assert resp.status_code == 200
        assert resp.json()["name"] == "new"

    async def test_update_policies(self, client: AsyncClient) -> None:
        create = await client.post("/roles", json={"name": "r"})
        rid = create.json()["id"]
        resp = await client.patch(f"/roles/{rid}", json={"user_permission": {"kind": "Denied"}})
        assert resp.status_code == 200
        assert resp.json()["user_permission"]["kind"] == "Denied"

    async def test_update_no_fields(self, client: AsyncClient) -> None:
        create = await client.post("/roles", json={"name": "keep"})
        rid = create.json()["id"]
        resp = await client.patch(f"/roles/{rid}", json={})
        assert resp.status_code == 200
        assert resp.json()["name"] == "keep"

    async def test_update_missing_role_returns_404(self, client: AsyncClient) -> None:
        resp = await client.patch(f"/roles/{uuid.uuid4()}", json={"name": "x"})
        assert resp.status_code == 404

    async def test_update_to_existing_name_conflict(self, client: AsyncClient, session) -> None:
        from openhands.ev2.role.role_models import Role
        from openhands.ev2.role.role_schemas import RoleCreate
        from openhands.ev2.role.role_service import RoleService
        from openhands.ev2.util.search_filter import AllSearchFilter

        await RoleService(session, AllSearchFilter[Role]()).create(RoleCreate(name="taken"))
        await session.commit()
        create = await client.post("/roles", json={"name": "other"})
        rid = create.json()["id"]
        resp = await client.patch(f"/roles/{rid}", json={"name": "taken"})
        assert resp.status_code == 409


class TestDeleteRoleRoute:
    async def test_delete_role(self, client: AsyncClient) -> None:
        create = await client.post("/roles", json={"name": "del"})
        rid = create.json()["id"]
        resp = await client.delete(f"/roles/{rid}")
        assert resp.status_code == 204
        assert (await client.get(f"/roles/{rid}")).status_code == 404

    async def test_delete_missing_role_returns_404(self, client: AsyncClient) -> None:
        resp = await client.delete(f"/roles/{uuid.uuid4()}")
        assert resp.status_code == 404


class TestPermissionEnforcement:
    """Tests for the permission check on role endpoints."""

    async def test_missing_auth_token_anonymous_denied(self, app) -> None:
        from httpx import ASGITransport, AsyncClient

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            resp = await ac.get("/roles")
        assert resp.status_code == 403

    async def test_invalid_auth_token_returns_401(self, client: AsyncClient) -> None:
        resp = await client.get("/roles", headers={"X-API-Key": "not-a-valid-token"})
        assert resp.status_code == 401

    async def test_denied_without_role(
        self, client: AsyncClient, session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        principal = await _make_principal(session, email="norole@example.com", username="norole")
        await session.commit()
        token = create_auth_token(principal.id)

        resp = await client.get("/roles", headers={"X-API-Key": token})
        assert resp.status_code == 403
        resp = await client.post("/roles", json={"name": "x"}, headers={"X-API-Key": token})
        assert resp.status_code == 403

    async def test_allowed_with_permitted_role(
        self, client: AsyncClient, session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        principal = await _make_principal(
            session, email="permitted@example.com", username="permitted"
        )
        await _assign_role(session, principal.id, {"role_permission": Permitted()})
        await session.commit()

        token = create_auth_token(principal.id)
        resp = await client.get("/roles", headers={"X-API-Key": token})
        assert resp.status_code == 200

    async def test_partial_permission_denies_other_action(
        self, client: AsyncClient, session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        principal = await _make_principal(
            session, email="readonly@example.com", username="readonly"
        )
        await _assign_role(session, principal.id, {"role_permission": ReadOnly()})
        await session.commit()

        token = create_auth_token(principal.id)
        resp = await client.get("/roles", headers={"X-API-Key": token})
        assert resp.status_code == 200
        resp = await client.post("/roles", json={"name": "new"}, headers={"X-API-Key": token})
        assert resp.status_code == 403
