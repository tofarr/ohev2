"""Route tests for the user feature (DB-backed, via ASGI client)."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from tests.unit._auth_helpers import assign_role as _assign_role
from tests.unit._auth_helpers import make_principal as _make_principal

from openhands.ev2.security.security_models import Permitted, ReadOnly
from openhands.ev2.util.auth_token import create_auth_token


class TestCreateUserRoute:
    async def test_create_user(self, client: AsyncClient) -> None:
        resp = await client.post("/users", json={"email": "alice@example.com", "username": "alice"})
        assert resp.status_code == 201
        body = resp.json()
        assert body["email"] == "alice@example.com"
        assert uuid.UUID(body["id"])
        assert body["created_at"] is not None

    async def test_create_duplicate_email_returns_409(self, client: AsyncClient) -> None:
        await client.post("/users", json={"email": "dup@example.com", "username": "dup"})
        resp2 = await client.post("/users", json={"email": "dup@example.com", "username": "dup2"})
        assert resp2.status_code == 409

    async def test_create_invalid_email_returns_422(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/users", json={"email": "not-an-email", "username": "not-an-email"}
        )
        assert resp.status_code == 422


class TestGetUserRoute:
    async def test_get_existing_user(self, client: AsyncClient) -> None:
        create = await client.post("/users", json={"email": "bob@example.com", "username": "bob"})
        uid = create.json()["id"]
        resp = await client.get(f"/users/{uid}")
        assert resp.status_code == 200
        assert resp.json()["email"] == "bob@example.com"

    async def test_get_missing_user_returns_404(self, client: AsyncClient) -> None:
        resp = await client.get(f"/users/{uuid.uuid4()}")
        assert resp.status_code == 404

    async def test_get_invalid_uuid_returns_422(self, client: AsyncClient) -> None:
        resp = await client.get("/users/not-a-uuid")
        assert resp.status_code == 422


class TestListUsersRoute:
    async def test_search_empty(self, client: AsyncClient) -> None:
        resp = await client.get("/users")
        assert resp.status_code == 200
        body = resp.json()
        # The conftest seeds a test-principal user, so the collection is never
        # truly empty; assert only the seeded row is present.
        assert len(body["items"]) == 1
        assert body["items"][0]["username"] == "test-principal"
        assert body["next_cursor"] is None
        assert body["limit"] == 50

    async def test_search_with_limit(self, client: AsyncClient) -> None:
        for i in range(3):
            await client.post("/users", json={"email": f"u{i}@example.com", "username": f"u{i}"})
        resp = await client.get("/users?limit=2")
        body = resp.json()
        assert len(body["items"]) == 2
        assert body["next_cursor"] is not None
        assert body["limit"] == 2

    async def test_search_pagination(self, client: AsyncClient) -> None:
        for i in range(4):
            await client.post("/users", json={"email": f"p{i}@example.com", "username": f"p{i}"})
        resp1 = await client.get("/users?limit=2")
        cursor = resp1.json()["next_cursor"]
        assert cursor is not None
        resp2 = await client.get(f"/users?limit=2&cursor={cursor}")
        assert resp2.status_code == 200
        assert len(resp2.json()["items"]) == 2

    async def test_search_invalid_cursor_returns_400(self, client: AsyncClient) -> None:
        resp = await client.get("/users?cursor=not-a-uuid")
        assert resp.status_code == 400

    async def test_search_limit_out_of_range_returns_422(self, client: AsyncClient) -> None:
        resp = await client.get("/users?limit=0")
        assert resp.status_code == 422
        resp = await client.get("/users?limit=101")
        assert resp.status_code == 422

    async def test_search_email_contains_filter(self, client: AsyncClient) -> None:
        await client.post("/users", json={"email": "Alice@Example.com", "username": "alice"})
        await client.post("/users", json={"email": "bob@example.com", "username": "bob"})
        await client.post("/users", json={"email": "charlie@other.org", "username": "charlie"})
        resp = await client.get("/users?email__contains=EXAMPLE")
        assert resp.status_code == 200
        emails = {u["email"] for u in resp.json()["items"]}
        # The seeded test-principal (test@example.com) also matches EXAMPLE.
        assert emails == {"Alice@example.com", "bob@example.com", "test@example.com"}

    async def test_search_email_contains_no_match(self, client: AsyncClient) -> None:
        await client.post("/users", json={"email": "alice@example.com", "username": "alice"})
        resp = await client.get("/users?email__contains=nonexistent")
        assert resp.status_code == 200
        assert resp.json()["items"] == []

    async def test_search_created_at_gte_filter(self, client: AsyncClient) -> None:
        create1 = await client.post("/users", json={"email": "old@example.com", "username": "old"})
        # Use the DB-side created_at as cutoff to avoid clock/precision skew.
        cutoff = create1.json()["created_at"]
        await client.post("/users", json={"email": "new@example.com", "username": "new"})
        resp = await client.get(f"/users?created_at__gte={cutoff}")
        assert resp.status_code == 200
        ids = {u["id"] for u in resp.json()["items"]}
        assert create1.json()["id"] in ids

    async def test_search_created_at_lt_filter(self, client: AsyncClient) -> None:
        create1 = await client.post("/users", json={"email": "old@example.com", "username": "old"})
        cutoff = create1.json()["created_at"]
        await client.post("/users", json={"email": "new@example.com", "username": "new"})
        resp = await client.get(f"/users?created_at__lt={cutoff}")
        assert resp.status_code == 200
        ids = {u["id"] for u in resp.json()["items"]}
        assert create1.json()["id"] not in ids

    async def test_search_combined_filters(self, client: AsyncClient) -> None:
        await client.post("/users", json={"email": "alice@example.com", "username": "alice"})
        await client.post("/users", json={"email": "bob@example.com", "username": "bob"})
        create3 = await client.post(
            "/users", json={"email": "alice@other.org", "username": "alice2"}
        )
        cutoff = create3.json()["created_at"]
        resp = await client.get(f"/users?email__contains=alice&created_at__gte={cutoff}")
        assert resp.status_code == 200
        emails = {u["email"] for u in resp.json()["items"]}
        assert emails == {"alice@other.org"}

    async def test_search_invalid_datetime_returns_422(self, client: AsyncClient) -> None:
        resp = await client.get("/users?created_at__gte=not-a-date")
        assert resp.status_code == 422


class TestCountUsersRoute:
    async def test_count_empty(self, client: AsyncClient) -> None:
        resp = await client.get("/users/count")
        assert resp.status_code == 200
        # The conftest seeds a test-principal user.
        assert resp.json() == {"count": 1}

    async def test_count_after_creates(self, client: AsyncClient) -> None:
        for i in range(3):
            await client.post("/users", json={"email": f"c{i}@example.com", "username": f"c{i}"})
        resp = await client.get("/users/count")
        assert resp.status_code == 200
        # 3 created + 1 seeded test-principal.
        assert resp.json()["count"] == 4

    async def test_count_with_email_filter(self, client: AsyncClient) -> None:
        await client.post("/users", json={"email": "alice@example.com", "username": "alice"})
        await client.post("/users", json={"email": "bob@example.com", "username": "bob"})
        resp = await client.get("/users/count?email__contains=alice")
        assert resp.status_code == 200
        assert resp.json()["count"] == 1

    async def test_count_excludes_deleted(self, client: AsyncClient) -> None:
        create = await client.post("/users", json={"email": "del@example.com", "username": "del"})
        await client.post("/users", json={"email": "keep@example.com", "username": "keep"})
        await client.delete(f"/users/{create.json()['id']}")
        resp = await client.get("/users/count")
        assert resp.status_code == 200
        # keep + 1 seeded test-principal (del was deleted).
        assert resp.json()["count"] == 2


class TestUpdateUserRoute:
    async def test_update_email(self, client: AsyncClient) -> None:
        create = await client.post("/users", json={"email": "old@example.com", "username": "old"})
        uid = create.json()["id"]
        resp = await client.patch(
            f"/users/{uid}", json={"email": "new@example.com", "username": "new"}
        )
        assert resp.status_code == 200
        assert resp.json()["email"] == "new@example.com"

    async def test_update_no_fields(self, client: AsyncClient) -> None:
        create = await client.post("/users", json={"email": "keep@example.com", "username": "keep"})
        uid = create.json()["id"]
        resp = await client.patch(f"/users/{uid}", json={})
        assert resp.status_code == 200
        assert resp.json()["email"] == "keep@example.com"

    async def test_update_missing_user_returns_404(self, client: AsyncClient) -> None:
        resp = await client.patch(
            f"/users/{uuid.uuid4()}", json={"email": "x@example.com", "username": "x"}
        )
        assert resp.status_code == 404


class TestDeleteUserRoute:
    async def test_delete_user(self, client: AsyncClient) -> None:
        create = await client.post("/users", json={"email": "del@example.com", "username": "del"})
        uid = create.json()["id"]
        resp = await client.delete(f"/users/{uid}")
        assert resp.status_code == 204
        get_resp = await client.get(f"/users/{uid}")
        assert get_resp.status_code == 404

    async def test_delete_missing_user_returns_404(self, client: AsyncClient) -> None:
        resp = await client.delete(f"/users/{uuid.uuid4()}")
        assert resp.status_code == 404


class TestPermissionEnforcement:
    """Tests for the permission check on user endpoints."""

    async def test_missing_auth_token_anonymous_denied(self, app) -> None:
        # No auth token at all -> anonymous; role-based authorization requires an
        # authenticated principal with a role, so protected endpoints return 403.
        from httpx import ASGITransport, AsyncClient

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            resp = await ac.get("/users")
        assert resp.status_code == 403

    async def test_invalid_auth_token_returns_401(self, client: AsyncClient) -> None:
        # A present-but-invalid token is a 401 (client claimed a principal).
        resp = await client.get("/users", headers={"X-API-Key": "not-a-valid-token"})
        assert resp.status_code == 401

    async def test_denied_without_role(
        self, client: AsyncClient, session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A principal with no role assigned is denied (403) on all actions."""
        principal = await _make_principal(session, email="norole@example.com", username="norole")
        await session.commit()
        token = create_auth_token(principal.id)

        resp = await client.get("/users", headers={"X-API-Key": token})
        assert resp.status_code == 403
        resp = await client.post(
            "/users",
            json={"email": "x@example.com", "username": "x"},
            headers={"X-API-Key": token},
        )
        assert resp.status_code == 403

    async def test_allowed_with_permitted_role(
        self, client: AsyncClient, session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A principal assigned a Permitted role for the user resource is allowed."""
        principal = await _make_principal(
            session, email="permitted@example.com", username="permitted"
        )
        await _assign_role(session, principal.id, {"user_permission": Permitted()})
        await session.commit()

        token = create_auth_token(principal.id)
        resp = await client.get("/users", headers={"X-API-Key": token})
        assert resp.status_code == 200

    async def test_partial_permission_denies_other_action(
        self, client: AsyncClient, session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A ReadOnly role grants SEARCH but not CREATE."""
        principal = await _make_principal(
            session, email="readonly@example.com", username="readonly"
        )
        await _assign_role(session, principal.id, {"user_permission": ReadOnly()})
        await session.commit()

        token = create_auth_token(principal.id)
        resp = await client.get("/users", headers={"X-API-Key": token})
        assert resp.status_code == 200
        resp = await client.post(
            "/users",
            json={"email": "new@example.com", "username": "new"},
            headers={"X-API-Key": token},
        )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# User router error paths (conflicts, not-found, count)
# ---------------------------------------------------------------------------


class TestUserRouterErrorPaths:
    async def test_count_endpoint(self, client: AsyncClient) -> None:
        resp = await client.get("/users/count")
        assert resp.status_code == 200
        assert resp.json()["count"] >= 1

    async def test_create_duplicate_email_409(self, client: AsyncClient, session) -> None:
        from openhands.ev2.user.user_models import User
        from openhands.ev2.user.user_schemas import UserCreate
        from openhands.ev2.user.user_service import UserService
        from openhands.ev2.util.search_filter import AllSearchFilter

        await UserService(session, AllSearchFilter[User]()).create(
            UserCreate(email="dup@example.com", username="dup1", password="hunter2")
        )
        await session.commit()
        resp = await client.post(
            "/users",
            json={
                "email": "dup@example.com",
                "username": "dup2",
                "password": "hunter2",
            },
        )
        assert resp.status_code == 409

    async def test_create_duplicate_username_409(self, client: AsyncClient, session) -> None:
        from openhands.ev2.user.user_models import User
        from openhands.ev2.user.user_schemas import UserCreate
        from openhands.ev2.user.user_service import UserService
        from openhands.ev2.util.search_filter import AllSearchFilter

        await UserService(session, AllSearchFilter[User]()).create(
            UserCreate(email="uniq@example.com", username="samename", password="hunter2")
        )
        await session.commit()
        resp = await client.post(
            "/users",
            json={
                "email": "other@example.com",
                "username": "samename",
                "password": "hunter2",
            },
        )
        assert resp.status_code == 409

    async def test_get_unknown_user_404(self, client: AsyncClient) -> None:
        resp = await client.get(f"/users/{uuid.uuid4()}")
        assert resp.status_code == 404

    async def test_update_unknown_user_404(self, client: AsyncClient) -> None:
        resp = await client.patch(f"/users/{uuid.uuid4()}", json={"email": "x@example.com"})
        assert resp.status_code == 404

    async def test_update_user_email_conflict(self, client: AsyncClient, session) -> None:
        from openhands.ev2.user.user_models import User
        from openhands.ev2.user.user_schemas import UserCreate
        from openhands.ev2.user.user_service import UserService
        from openhands.ev2.util.search_filter import AllSearchFilter

        await UserService(session, AllSearchFilter[User]()).create(
            UserCreate(email="a@example.com", username="ua", password="hunter2")
        )
        target = await UserService(session, AllSearchFilter[User]()).create(
            UserCreate(email="b@example.com", username="ub", password="hunter2")
        )
        await session.commit()
        resp = await client.patch(f"/users/{target.id}", json={"email": "a@example.com"})
        assert resp.status_code == 409

    async def test_update_user_username_conflict(self, client: AsyncClient, session) -> None:
        from openhands.ev2.user.user_models import User
        from openhands.ev2.user.user_schemas import UserCreate
        from openhands.ev2.user.user_service import UserService
        from openhands.ev2.util.search_filter import AllSearchFilter

        await UserService(session, AllSearchFilter[User]()).create(
            UserCreate(email="c@example.com", username="uc", password="hunter2")
        )
        target = await UserService(session, AllSearchFilter[User]()).create(
            UserCreate(email="d@example.com", username="ud", password="hunter2")
        )
        await session.commit()
        resp = await client.patch(f"/users/{target.id}", json={"username": "uc"})
        assert resp.status_code == 409

    async def test_update_user_success(self, client: AsyncClient, session) -> None:
        from openhands.ev2.user.user_models import User
        from openhands.ev2.user.user_schemas import UserCreate
        from openhands.ev2.user.user_service import UserService
        from openhands.ev2.util.search_filter import AllSearchFilter

        target = await UserService(session, AllSearchFilter[User]()).create(
            UserCreate(email="upd@example.com", username="upd", password="hunter2")
        )
        await session.commit()
        resp = await client.patch(f"/users/{target.id}", json={"enabled": False})
        assert resp.status_code == 200
        assert resp.json()["enabled"] is False
