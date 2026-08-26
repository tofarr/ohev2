"""Route tests for the user feature (DB-backed, via ASGI client)."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient

from ohev.permission.permission_service import reset_base_permissions_cache


class TestCreateUserRoute:
    async def test_create_user(self, client: AsyncClient) -> None:
        resp = await client.post("/users", json={"email": "alice@example.com"})
        assert resp.status_code == 201
        body = resp.json()
        assert body["email"] == "alice@example.com"
        assert uuid.UUID(body["id"])
        assert body["created_at"] is not None

    async def test_create_duplicate_email_returns_409(self, client: AsyncClient) -> None:
        payload = {"email": "dup@example.com"}
        resp = await client.post("/users", json=payload)
        assert resp.status_code == 201
        resp2 = await client.post("/users", json=payload)
        assert resp2.status_code == 409

    async def test_create_invalid_email_returns_422(self, client: AsyncClient) -> None:
        resp = await client.post("/users", json={"email": "not-an-email"})
        assert resp.status_code == 422


class TestGetUserRoute:
    async def test_get_existing_user(self, client: AsyncClient) -> None:
        create = await client.post("/users", json={"email": "bob@example.com"})
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
        assert body["items"] == []
        assert body["next_cursor"] is None
        assert body["limit"] == 50

    async def test_search_with_limit(self, client: AsyncClient) -> None:
        for i in range(3):
            await client.post("/users", json={"email": f"u{i}@example.com"})
        resp = await client.get("/users?limit=2")
        body = resp.json()
        assert len(body["items"]) == 2
        assert body["next_cursor"] is not None
        assert body["limit"] == 2

    async def test_search_pagination(self, client: AsyncClient) -> None:
        for i in range(4):
            await client.post("/users", json={"email": f"p{i}@example.com"})
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
        await client.post("/users", json={"email": "Alice@Example.com"})
        await client.post("/users", json={"email": "bob@example.com"})
        await client.post("/users", json={"email": "charlie@other.org"})
        resp = await client.get("/users?email__contains=EXAMPLE")
        assert resp.status_code == 200
        emails = {u["email"] for u in resp.json()["items"]}
        assert emails == {"Alice@example.com", "bob@example.com"}

    async def test_search_email_contains_no_match(self, client: AsyncClient) -> None:
        await client.post("/users", json={"email": "alice@example.com"})
        resp = await client.get("/users?email__contains=nonexistent")
        assert resp.status_code == 200
        assert resp.json()["items"] == []

    async def test_search_created_at_gte_filter(self, client: AsyncClient) -> None:
        create1 = await client.post("/users", json={"email": "old@example.com"})
        # Use the DB-side created_at as cutoff to avoid clock/precision skew.
        cutoff = create1.json()["created_at"]
        await client.post("/users", json={"email": "new@example.com"})
        resp = await client.get(f"/users?created_at__gte={cutoff}")
        assert resp.status_code == 200
        ids = {u["id"] for u in resp.json()["items"]}
        assert create1.json()["id"] in ids

    async def test_search_created_at_lt_filter(self, client: AsyncClient) -> None:
        create1 = await client.post("/users", json={"email": "old@example.com"})
        cutoff = create1.json()["created_at"]
        await client.post("/users", json={"email": "new@example.com"})
        resp = await client.get(f"/users?created_at__lt={cutoff}")
        assert resp.status_code == 200
        ids = {u["id"] for u in resp.json()["items"]}
        assert create1.json()["id"] not in ids

    async def test_search_combined_filters(self, client: AsyncClient) -> None:
        await client.post("/users", json={"email": "alice@example.com"})
        await client.post("/users", json={"email": "bob@example.com"})
        create3 = await client.post("/users", json={"email": "alice@other.org"})
        cutoff = create3.json()["created_at"]
        resp = await client.get(f"/users?email__contains=alice&created_at__gte={cutoff}")
        assert resp.status_code == 200
        emails = {u["email"] for u in resp.json()["items"]}
        assert emails == {"alice@other.org"}

    async def test_search_invalid_datetime_returns_422(self, client: AsyncClient) -> None:
        resp = await client.get("/users?created_at__gte=not-a-date")
        assert resp.status_code == 422


class TestUpdateUserRoute:
    async def test_update_email(self, client: AsyncClient) -> None:
        create = await client.post("/users", json={"email": "old@example.com"})
        uid = create.json()["id"]
        resp = await client.patch(f"/users/{uid}", json={"email": "new@example.com"})
        assert resp.status_code == 200
        assert resp.json()["email"] == "new@example.com"

    async def test_update_no_fields(self, client: AsyncClient) -> None:
        create = await client.post("/users", json={"email": "keep@example.com"})
        uid = create.json()["id"]
        resp = await client.patch(f"/users/{uid}", json={})
        assert resp.status_code == 200
        assert resp.json()["email"] == "keep@example.com"

    async def test_update_missing_user_returns_404(self, client: AsyncClient) -> None:
        resp = await client.patch(f"/users/{uuid.uuid4()}", json={"email": "x@example.com"})
        assert resp.status_code == 404


class TestDeleteUserRoute:
    async def test_delete_user(self, client: AsyncClient) -> None:
        create = await client.post("/users", json={"email": "del@example.com"})
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

    async def test_missing_auth_header_anonymous_allowed(self, app) -> None:
        # Auth is optional; without X-User-Id the request is treated as
        # anonymous and the baseline permissions grant access (200).
        from httpx import ASGITransport, AsyncClient

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            resp = await ac.get("/users")
        assert resp.status_code == 200

    async def test_invalid_auth_header_returns_401(self, client: AsyncClient) -> None:
        resp = await client.get("/users", headers={"X-User-Id": "not-a-uuid"})
        assert resp.status_code == 401

    async def test_denied_without_permission(
        self, client: AsyncClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With empty base permissions and no DB grant, all user endpoints return 403."""
        from ohev.config import get_config

        get_config.cache_clear()
        reset_base_permissions_cache()
        monkeypatch.delenv("OHEV_BASE_PERMISSIONS_0", raising=False)
        monkeypatch.delenv("OHEV_BASE_PERMISSIONS_1", raising=False)
        monkeypatch.setenv("OHEV_BASE_PERMISSIONS_0", "")

        resp = await client.get("/users")
        assert resp.status_code == 403
        resp = await client.post("/users", json={"email": "x@example.com"})
        assert resp.status_code == 403

    async def test_allowed_with_db_permission(
        self, client: AsyncClient, session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A per-user DB grant allows access even with empty base permissions."""
        from ohev.config import get_config

        get_config.cache_clear()
        reset_base_permissions_cache()
        monkeypatch.delenv("OHEV_BASE_PERMISSIONS_0", raising=False)
        monkeypatch.delenv("OHEV_BASE_PERMISSIONS_1", raising=False)
        monkeypatch.setenv("OHEV_BASE_PERMISSIONS_0", "")

        from ohev.permission.permission_models import Action, Permission, ResourceType
        from ohev.permission.permission_schemas import PermissionCreate
        from ohev.permission.permission_service import PermissionService
        from ohev.user.user_models import User
        from ohev.user.user_schemas import UserCreate
        from ohev.user.user_service import UserService
        from ohev.util.search_filter import AllSearchFilter

        # Create the principal user directly in the DB (bypassing the API,
        # which is itself permission-guarded).
        principal = await UserService(session).create(
            UserCreate(email="principal@example.com"), AllSearchFilter[User]()
        )
        principal_id = principal.id

        service = PermissionService(session)
        await service.create(
            PermissionCreate(
                user_id=principal_id,
                action=Action.SEARCH,
                resource_type=ResourceType.USER,
            ),
            AllSearchFilter[Permission](),
        )
        await session.commit()

        # Use the principal's id as X-User-Id for this request.
        resp = await client.get("/users", headers={"X-User-Id": str(principal_id)})
        assert resp.status_code == 200

    async def test_partial_permission_denies_other_action(
        self, client: AsyncClient, session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A SEARCH grant does not allow CREATE."""
        from ohev.config import get_config

        get_config.cache_clear()
        reset_base_permissions_cache()
        monkeypatch.delenv("OHEV_BASE_PERMISSIONS_0", raising=False)
        monkeypatch.delenv("OHEV_BASE_PERMISSIONS_1", raising=False)
        monkeypatch.setenv("OHEV_BASE_PERMISSIONS_0", "")

        from ohev.permission.permission_models import Action, Permission, ResourceType
        from ohev.permission.permission_schemas import PermissionCreate
        from ohev.permission.permission_service import PermissionService
        from ohev.user.user_models import User
        from ohev.user.user_schemas import UserCreate
        from ohev.user.user_service import UserService
        from ohev.util.search_filter import AllSearchFilter

        principal = await UserService(session).create(
            UserCreate(email="principal@example.com"), AllSearchFilter[User]()
        )
        principal_id = principal.id

        service = PermissionService(session)
        await service.create(
            PermissionCreate(
                user_id=principal_id,
                action=Action.SEARCH,
                resource_type=ResourceType.USER,
            ),
            AllSearchFilter[Permission](),
        )
        await session.commit()

        resp = await client.get("/users", headers={"X-User-Id": str(principal_id)})
        assert resp.status_code == 200
        resp = await client.post(
            "/users",
            json={"email": "new@example.com"},
            headers={"X-User-Id": str(principal_id)},
        )
        assert resp.status_code == 403
