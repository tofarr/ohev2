"""Route tests for the user feature (DB-backed, via ASGI client)."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient

from ohev.permission.permission_service import reset_base_permissions_cache


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

    async def test_missing_auth_token_anonymous_allowed(self, app) -> None:
        # No auth token at all → anonymous; baseline permissions grant 200.
        from httpx import ASGITransport, AsyncClient

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            resp = await ac.get("/users")
        assert resp.status_code == 200

    async def test_invalid_auth_token_returns_401(self, client: AsyncClient) -> None:
        # A present-but-invalid token is a 401 (client claimed a principal).
        resp = await client.get("/users", headers={"X-API-Key": "not-a-valid-token"})
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
        resp = await client.post("/users", json={"email": "x@example.com", "username": "x"})
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
        from ohev.util.auth_token import create_auth_token
        from ohev.util.search_filter import AllSearchFilter

        # Create the principal user directly in the DB (bypassing the API,
        # which is itself permission-guarded).
        principal = await UserService(session, AllSearchFilter[User]()).create(
            UserCreate(email="principal@example.com", username="principal")
        )
        principal_id = principal.id

        service = PermissionService(session, AllSearchFilter[Permission]())
        await service.create(
            PermissionCreate(
                user_id=principal_id,
                action=Action.SEARCH,
                resource_type=ResourceType.USER,
            ),
        )
        await session.commit()

        # Mint a real JWE token for the principal and send it as X-API-Key.
        token = create_auth_token(principal_id)
        resp = await client.get("/users", headers={"X-API-Key": token})
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
        from ohev.util.auth_token import create_auth_token
        from ohev.util.search_filter import AllSearchFilter

        principal = await UserService(session, AllSearchFilter[User]()).create(
            UserCreate(email="principal@example.com", username="principal")
        )
        principal_id = principal.id

        service = PermissionService(session, AllSearchFilter[Permission]())
        await service.create(
            PermissionCreate(
                user_id=principal_id,
                action=Action.SEARCH,
                resource_type=ResourceType.USER,
            ),
        )
        await session.commit()

        token = create_auth_token(principal_id)
        resp = await client.get("/users", headers={"X-API-Key": token})
        assert resp.status_code == 200
        resp = await client.post(
            "/users",
            json={"email": "new@example.com", "username": "new"},
            headers={"X-API-Key": token},
        )
        assert resp.status_code == 403


class TestLoginRoute:
    """POST /auth/login mints a JWE auth cookie."""

    async def test_login_success_sets_cookie_and_returns_user(
        self, client: AsyncClient, session
    ) -> None:
        from ohev.user.user_models import User
        from ohev.user.user_schemas import UserCreate
        from ohev.user.user_service import UserService
        from ohev.util.search_filter import AllSearchFilter

        await UserService(session, AllSearchFilter[User]()).create(
            UserCreate(email="alice@example.com", username="alice", password="hunter2")
        )
        await session.commit()

        resp = await client.post("/auth/login", json={"username": "alice", "password": "hunter2"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["username"] == "alice"
        assert body["token_type"] == "cookie"
        # Cookie set with the configured name.
        assert "ohesession" in resp.cookies

    async def test_login_bad_password_returns_401(self, client: AsyncClient, session) -> None:
        from ohev.user.user_models import User
        from ohev.user.user_schemas import UserCreate
        from ohev.user.user_service import UserService
        from ohev.util.search_filter import AllSearchFilter

        await UserService(session, AllSearchFilter[User]()).create(
            UserCreate(email="alice@example.com", username="alice", password="hunter2")
        )
        await session.commit()

        resp = await client.post("/auth/login", json={"username": "alice", "password": "wrong"})
        assert resp.status_code == 401
        assert "ohesession" not in resp.cookies

    async def test_login_unknown_user_returns_401(self, client: AsyncClient) -> None:
        resp = await client.post("/auth/login", json={"username": "nobody", "password": "x"})
        assert resp.status_code == 401

    async def test_login_disabled_user_returns_401(self, client: AsyncClient, session) -> None:
        from ohev.user.user_models import User
        from ohev.user.user_schemas import UserCreate
        from ohev.user.user_service import UserService
        from ohev.util.search_filter import AllSearchFilter

        await UserService(session, AllSearchFilter[User]()).create(
            UserCreate(
                email="alice@example.com",
                username="alice",
                password="hunter2",
                enabled=False,
            )
        )
        await session.commit()

        resp = await client.post("/auth/login", json={"username": "alice", "password": "hunter2"})
        assert resp.status_code == 401

    async def test_login_token_authenticates_subsequent_request(
        self, app, session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The cookie minted by login authorizes a follow-up request via the
        cookie fallback in get_current_user_id."""
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

        principal = await UserService(session, AllSearchFilter[User]()).create(
            UserCreate(email="alice@example.com", username="alice", password="hunter2")
        )
        principal_id = principal.id
        psvc = PermissionService(session, AllSearchFilter[Permission]())
        await psvc.create(
            PermissionCreate(
                user_id=principal_id,
                action=Action.SEARCH,
                resource_type=ResourceType.USER,
            ),
        )
        await session.commit()

        # A bare client (no X-API-Key) that performs login then reuses the cookie.
        # The cookie is Secure, so httpx will not auto-replay it over the plain
        # http://test transport; send it explicitly via the Cookie header to
        # exercise the cookie-fallback branch of get_current_user_id.
        from httpx import ASGITransport, AsyncClient

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            login = await ac.post("/auth/login", json={"username": "alice", "password": "hunter2"})
            assert login.status_code == 200
            cookie_token = login.cookies["ohesession"]
            resp = await ac.get("/users", headers={"Cookie": f"ohesession={cookie_token}"})
            assert resp.status_code == 200

    async def test_login_bearer_token_authorizes_request(
        self, app, session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The bearer-token fallback in get_current_user_id accepts the login token."""
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

        principal = await UserService(session, AllSearchFilter[User]()).create(
            UserCreate(email="alice@example.com", username="alice", password="hunter2")
        )
        principal_id = principal.id
        psvc = PermissionService(session, AllSearchFilter[Permission]())
        await psvc.create(
            PermissionCreate(
                user_id=principal_id,
                action=Action.SEARCH,
                resource_type=ResourceType.USER,
            ),
        )
        await session.commit()

        from httpx import ASGITransport, AsyncClient

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            login = await ac.post("/auth/login", json={"username": "alice", "password": "hunter2"})
            assert login.status_code == 200
            # The token lives in the cookie; send it as a Bearer header instead
            # to exercise the Authorization fallback path.
            cookie_token = login.cookies["ohesession"]
            resp = await ac.get("/users", headers={"Authorization": f"Bearer {cookie_token}"})
            assert resp.status_code == 200


class TestLogoutRoute:
    """POST /users/logout clears the session cookie."""

    async def test_logout_returns_204(self, client: AsyncClient) -> None:
        resp = await client.post("/auth/logout")
        assert resp.status_code == 204

    async def test_logout_clears_session_cookie(
        self, app, session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """After logout the session cookie is expired (max-age=0) so the
        client drops it and subsequent requests are unauthenticated."""
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

        principal = await UserService(session, AllSearchFilter[User]()).create(
            UserCreate(email="alice@example.com", username="alice", password="hunter2")
        )
        psvc = PermissionService(session, AllSearchFilter[Permission]())
        await psvc.create(
            PermissionCreate(
                user_id=principal.id,
                action=Action.SEARCH,
                resource_type=ResourceType.USER,
            ),
        )
        await session.commit()

        from httpx import ASGITransport, AsyncClient

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            login = await ac.post("/auth/login", json={"username": "alice", "password": "hunter2"})
            assert login.status_code == 200
            assert "ohesession" in ac.cookies

            logout = await ac.post("/auth/logout")
            assert logout.status_code == 204
            # delete_cookie sets max-age=0, which the client applies: the
            # stored cookie is removed from the client jar.
            assert "ohesession" not in ac.cookies

    async def test_logout_without_session_is_noop(self, client: AsyncClient) -> None:
        """Logging out when no session cookie exists still returns 204."""
        resp = await client.post("/auth/logout")
        assert resp.status_code == 204


# ---------------------------------------------------------------------------
# User router error paths (conflicts, not-found, count)
# ---------------------------------------------------------------------------


class TestUserRouterErrorPaths:
    async def test_count_endpoint(self, client: AsyncClient) -> None:
        resp = await client.get("/users/count")
        assert resp.status_code == 200
        assert resp.json()["count"] >= 1

    async def test_create_duplicate_email_409(self, client: AsyncClient, session) -> None:
        from ohev.user.user_models import User
        from ohev.user.user_schemas import UserCreate
        from ohev.user.user_service import UserService
        from ohev.util.search_filter import AllSearchFilter

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
        from ohev.user.user_models import User
        from ohev.user.user_schemas import UserCreate
        from ohev.user.user_service import UserService
        from ohev.util.search_filter import AllSearchFilter

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
        from ohev.user.user_models import User
        from ohev.user.user_schemas import UserCreate
        from ohev.user.user_service import UserService
        from ohev.util.search_filter import AllSearchFilter

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
        from ohev.user.user_models import User
        from ohev.user.user_schemas import UserCreate
        from ohev.user.user_service import UserService
        from ohev.util.search_filter import AllSearchFilter

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
        from ohev.user.user_models import User
        from ohev.user.user_schemas import UserCreate
        from ohev.user.user_service import UserService
        from ohev.util.search_filter import AllSearchFilter

        target = await UserService(session, AllSearchFilter[User]()).create(
            UserCreate(email="upd@example.com", username="upd", password="hunter2")
        )
        await session.commit()
        resp = await client.patch(f"/users/{target.id}", json={"enabled": False})
        assert resp.status_code == 200
        assert resp.json()["enabled"] is False
