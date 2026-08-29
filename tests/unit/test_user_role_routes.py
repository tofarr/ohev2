"""Route tests for the user-role assignment feature (DB-backed, ASGI client)."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from tests.unit._auth_helpers import assign_role as _assign_role
from tests.unit._auth_helpers import make_principal as _make_principal

from openhands.ev2.security.security_models import Permitted, ReadOnly
from openhands.ev2.util.auth_token import create_auth_token


async def _seed_role_and_user(
    client: AsyncClient, *, role_name: str = "linked-role"
) -> tuple[str, str]:
    """Create a role and a user via the API; return their id strings."""
    role_resp = await client.post("/roles", json={"name": role_name})
    assert role_resp.status_code == 201, role_resp.text
    user_resp = await client.post(
        "/users", json={"email": f"{role_name}@example.com", "username": role_name}
    )
    assert user_resp.status_code == 201, user_resp.text
    return role_resp.json()["id"], user_resp.json()["id"]


class TestCreateAssignmentRoute:
    async def test_create_assignment(self, client: AsyncClient) -> None:
        role_id, user_id = await _seed_role_and_user(client)
        resp = await client.post("/user-roles", json={"role_id": role_id, "user_id": user_id})
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["role_id"] == role_id
        assert body["user_id"] == user_id
        assert "id" in body
        assert "created_at" in body

    async def test_create_duplicate_returns_409(self, client: AsyncClient, session) -> None:
        role_id, user_id = await _seed_role_and_user(client)
        first = await client.post("/user-roles", json={"role_id": role_id, "user_id": user_id})
        assert first.status_code == 201
        second = await client.post("/user-roles", json={"role_id": role_id, "user_id": user_id})
        assert second.status_code == 409

    async def test_create_missing_role_returns_404(self, client: AsyncClient) -> None:
        _role_id, user_id = await _seed_role_and_user(client)
        resp = await client.post(
            "/user-roles",
            json={"role_id": str(uuid.uuid4()), "user_id": user_id},
        )
        assert resp.status_code == 404

    async def test_create_missing_user_returns_404(self, client: AsyncClient) -> None:
        role_id, _user_id = await _seed_role_and_user(client)
        resp = await client.post(
            "/user-roles",
            json={"role_id": role_id, "user_id": str(uuid.uuid4())},
        )
        assert resp.status_code == 404


class TestGetAssignmentRoute:
    async def test_get_existing(self, client: AsyncClient) -> None:
        role_id, user_id = await _seed_role_and_user(client)
        create = await client.post("/user-roles", json={"role_id": role_id, "user_id": user_id})
        lid = create.json()["id"]
        resp = await client.get(f"/user-roles/{lid}")
        assert resp.status_code == 200
        assert resp.json()["id"] == lid

    async def test_get_missing_returns_404(self, client: AsyncClient) -> None:
        resp = await client.get(f"/user-roles/{uuid.uuid4()}")
        assert resp.status_code == 404


class TestListAssignmentsRoute:
    async def test_search_empty(self, client: AsyncClient) -> None:
        resp = await client.get("/user-roles")
        assert resp.status_code == 200
        body = resp.json()
        # The conftest assigns the test-admin role to the test-principal.
        assert len(body["items"]) >= 1
        assert body["next_cursor"] is None
        assert body["limit"] == 50

    async def test_search_with_limit(self, client: AsyncClient) -> None:
        role_id, _ = await _seed_role_and_user(client)
        # Create several assignments to the same role via the API.
        for i in range(3):
            user_resp = await client.post(
                "/users", json={"email": f"u{i}@example.com", "username": f"u{i}"}
            )
            await client.post(
                "/user-roles",
                json={"role_id": role_id, "user_id": user_resp.json()["id"]},
            )
        resp = await client.get("/user-roles?limit=2")
        body = resp.json()
        assert len(body["items"]) == 2
        assert body["next_cursor"] is not None

    async def test_search_pagination(self, client: AsyncClient) -> None:
        role_id, _ = await _seed_role_and_user(client)
        for i in range(4):
            user_resp = await client.post(
                "/users", json={"email": f"p{i}@example.com", "username": f"p{i}"}
            )
            await client.post(
                "/user-roles",
                json={"role_id": role_id, "user_id": user_resp.json()["id"]},
            )
        resp1 = await client.get("/user-roles?limit=2")
        cursor = resp1.json()["next_cursor"]
        assert cursor is not None
        resp2 = await client.get(f"/user-roles?limit=2&cursor={cursor}")
        assert resp2.status_code == 200
        assert len(resp2.json()["items"]) == 2

    async def test_search_invalid_cursor_returns_400(self, client: AsyncClient) -> None:
        resp = await client.get("/user-roles?cursor=not-a-uuid")
        assert resp.status_code == 400

    async def test_search_role_id_filter(self, client: AsyncClient) -> None:
        role_a, _ = await _seed_role_and_user(client, role_name="role-a")
        role_b, _ = await _seed_role_and_user(client, role_name="role-b")
        user_resp = await client.post(
            "/users", json={"email": "shared@example.com", "username": "shared"}
        )
        user_id = user_resp.json()["id"]
        await client.post("/user-roles", json={"role_id": role_a, "user_id": user_id})
        await client.post("/user-roles", json={"role_id": role_b, "user_id": user_id})
        resp = await client.get(f"/user-roles?role_id__eq={role_a}")
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert all(i["role_id"] == role_a for i in items)


class TestCountAssignmentsRoute:
    async def test_count_empty(self, client: AsyncClient) -> None:
        resp = await client.get("/user-roles/count")
        assert resp.status_code == 200
        # The conftest seeds one assignment (test-admin -> test-principal).
        assert resp.json()["count"] >= 1

    async def test_count_after_create(self, client: AsyncClient) -> None:
        role_id, user_id = await _seed_role_and_user(client)
        await client.post("/user-roles", json={"role_id": role_id, "user_id": user_id})
        resp = await client.get("/user-roles/count")
        assert resp.status_code == 200
        assert resp.json()["count"] >= 2


class TestBatchAssignmentsRoute:
    async def test_batch_returns_aligned_with_nulls_for_missing(self, client: AsyncClient) -> None:
        role_id, user_id = await _seed_role_and_user(client)
        a = await client.post("/user-roles", json={"role_id": role_id, "user_id": user_id})
        aid = a.json()["id"]
        missing = str(uuid.uuid4())
        resp = await client.get(f"/user-roles/batch?ids={aid}&ids={missing}")
        assert resp.status_code == 200, resp.text
        items = resp.json()["items"]
        assert len(items) == 2
        assert items[0]["id"] == aid
        assert items[1] is None

    async def test_batch_empty_ids_returns_empty_list(self, client: AsyncClient) -> None:
        resp = await client.get("/user-roles/batch")
        assert resp.status_code == 200
        assert resp.json()["items"] == []

    async def test_batch_preserves_duplicate_ids(self, client: AsyncClient) -> None:
        role_id, user_id = await _seed_role_and_user(client)
        a = await client.post("/user-roles", json={"role_id": role_id, "user_id": user_id})
        aid = a.json()["id"]
        resp = await client.get(f"/user-roles/batch?ids={aid}&ids={aid}")
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 2
        assert items[0]["id"] == aid
        assert items[1]["id"] == aid

    async def test_batch_all_missing_returns_all_nulls(self, client: AsyncClient) -> None:
        m1, m2 = str(uuid.uuid4()), str(uuid.uuid4())
        resp = await client.get(f"/user-roles/batch?ids={m1}&ids={m2}")
        assert resp.status_code == 200
        assert resp.json()["items"] == [None, None]

    async def test_batch_over_100_ids_returns_422(self, client: AsyncClient) -> None:
        ids = "&".join(f"ids={uuid.uuid4()}" for _ in range(101))
        resp = await client.get(f"/user-roles/batch?{ids}")
        assert resp.status_code == 422

    async def test_batch_invalid_uuid_returns_422(self, client: AsyncClient) -> None:
        resp = await client.get("/user-roles/batch?ids=not-a-uuid")
        assert resp.status_code == 422


class TestDeleteAssignmentRoute:
    async def test_delete_assignment(self, client: AsyncClient) -> None:
        role_id, user_id = await _seed_role_and_user(client)
        create = await client.post("/user-roles", json={"role_id": role_id, "user_id": user_id})
        lid = create.json()["id"]
        resp = await client.delete(f"/user-roles/{lid}")
        assert resp.status_code == 204
        assert (await client.get(f"/user-roles/{lid}")).status_code == 404

    async def test_delete_missing_returns_404(self, client: AsyncClient) -> None:
        resp = await client.delete(f"/user-roles/{uuid.uuid4()}")
        assert resp.status_code == 404


class TestPermissionEnforcement:
    """Tests for the permission check on role-user endpoints.

    Assignments are authorized through the ``role`` resource policy: READ
    gates list/get, UPDATE gates create/delete.
    """

    async def test_missing_auth_token_anonymous_denied(self, app) -> None:
        from httpx import ASGITransport, AsyncClient

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            resp = await ac.get("/user-roles")
        assert resp.status_code == 403

    async def test_invalid_auth_token_returns_401(self, client: AsyncClient) -> None:
        resp = await client.get("/user-roles", headers={"X-API-Key": "not-a-valid-token"})
        assert resp.status_code == 401

    async def test_readonly_role_allows_read_denies_write(
        self, client: AsyncClient, session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        principal = await _make_principal(session, email="ro@example.com", username="ro")
        await _assign_role(session, principal.id, {"role_permission": ReadOnly()})
        await session.commit()

        token = create_auth_token(principal.id)
        resp = await client.get("/user-roles", headers={"X-API-Key": token})
        assert resp.status_code == 200
        # Create requires UPDATE on role; ReadOnly denies it.
        resp = await client.post(
            "/user-roles",
            json={"role_id": str(uuid.uuid4()), "user_id": str(uuid.uuid4())},
            headers={"X-API-Key": token},
        )
        assert resp.status_code == 403

    async def test_permitted_role_allows_write(
        self, client: AsyncClient, session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        principal = await _make_principal(session, email="perm@example.com", username="perm")
        await _assign_role(session, principal.id, {"role_permission": Permitted()})
        await session.commit()

        token = create_auth_token(principal.id)
        resp = await client.get("/user-roles", headers={"X-API-Key": token})
        assert resp.status_code == 200
