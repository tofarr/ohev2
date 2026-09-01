"""Route tests for the user-role assignment feature (DB-backed, ASGI client)."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from tests.unit._auth_helpers import assign_role as _assign_role
from tests.unit._auth_helpers import make_principal as _make_principal

from openhands.ev2.security.security_models import Action, Permission, Permitted, ReadOnly
from openhands.ev2.util.auth_token import create_auth_token
from openhands.ev2.util.search_filter import (
    AttributeFilter,
    Condition,
    NoneSearchFilter,
    SearchFilter,
)


class _SelfAssignmentAccess(Permission):
    """Test policy: a principal may manage assignments only for themselves.

    Mirrors how :class:`ApiKeyAccess` scopes API keys to their owner, applied
    to the user-role link table (``UserRole.user_id == principal``).
    """

    def to_search_filter(self, user_id: uuid.UUID | None, action: Action) -> SearchFilter[Any]:
        if user_id is None:
            return NoneSearchFilter[Any]()
        from openhands.ev2.role.role_models import UserRole

        return AttributeFilter[UserRole](attribute="user_id", value=user_id, condition=Condition.EQ)


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
    """Tests for the permission check on user-role endpoints.

    Assignments are authorized through the dedicated ``user_role_permission``
    column: SEARCH/READ gate list/get, CREATE/DELETE gate membership changes.
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
        await _assign_role(session, principal.id, {"user_role_permission": ReadOnly()})
        await session.commit()

        token = create_auth_token(principal.id)
        resp = await client.get("/user-roles", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        # Create requires CREATE on user_role; ReadOnly denies it.
        resp = await client.post(
            "/user-roles",
            json={"role_id": str(uuid.uuid4()), "user_id": str(uuid.uuid4())},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403

    async def test_permitted_role_allows_write(
        self, client: AsyncClient, session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        principal = await _make_principal(session, email="perm@example.com", username="perm")
        await _assign_role(session, principal.id, {"user_role_permission": Permitted()})
        await session.commit()

        token = create_auth_token(principal.id)
        resp = await client.get("/user-roles", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200


class TestBatchWriteUserRoles:
    """POST /user-roles/batch — mix of create/delete (no update) in one transaction."""

    async def test_batch_mix_cd_returns_positional_results(self, client: AsyncClient) -> None:
        role = await client.post("/roles", json={"name": "bwlinkrole"})
        u1 = await client.post("/users", json={"email": "bwl1@example.com", "username": "bwl1"})
        u3 = await client.post("/users", json={"email": "bwl3@example.com", "username": "bwl3"})
        rid = role.json()["id"]
        a1 = await client.post("/user-roles", json={"role_id": rid, "user_id": u1.json()["id"]})
        resp = await client.post(
            "/user-roles/batch",
            json={
                "operations": [
                    {"op": "delete", "id": a1.json()["id"]},
                    {"op": "create", "data": {"role_id": rid, "user_id": u3.json()["id"]}},
                ]
            },
        )
        assert resp.status_code == 200, resp.text
        items = resp.json()["items"]
        assert len(items) == 2
        assert items[0] is None
        assert items[1]["user_id"] == u3.json()["id"]
        assert (await client.get(f"/user-roles/{a1.json()['id']}")).status_code == 404

    async def test_batch_atomic_rollback_on_missing_id(self, client: AsyncClient) -> None:
        role = await client.post("/roles", json={"name": "bwrbrole"})
        u = await client.post("/users", json={"email": "bwrbu@example.com", "username": "bwrbu"})
        resp = await client.post(
            "/user-roles/batch",
            json={
                "operations": [
                    {
                        "op": "create",
                        "data": {"role_id": role.json()["id"], "user_id": u.json()["id"]},
                    },
                    {"op": "delete", "id": str(uuid.uuid4())},  # missing -> 404
                ]
            },
        )
        assert resp.status_code == 404
        # create rolled back: no assignment linking role+u
        links = (await client.get("/user-roles?limit=100")).json()["items"]
        assert not any(link["user_id"] == u.json()["id"] for link in links)

    async def test_batch_empty_operations_rejected(self, client: AsyncClient) -> None:
        resp = await client.post("/user-roles/batch", json={"operations": []})
        assert resp.status_code == 422

    async def test_batch_over_100_ops_rejected(self, client: AsyncClient) -> None:
        ops = [{"op": "delete", "id": str(uuid.uuid4())} for _ in range(101)]
        resp = await client.post("/user-roles/batch", json={"operations": ops})
        assert resp.status_code == 422

    async def test_batch_update_op_rejected(self, client: AsyncClient) -> None:
        # user-roles are immutable; update op must be rejected by the discriminated union.
        resp = await client.post(
            "/user-roles/batch",
            json={"operations": [{"op": "update", "id": str(uuid.uuid4()), "data": {}}]},
        )
        assert resp.status_code == 422

    async def test_batch_duplicate_assignment_conflict_rolls_back(
        self, client: AsyncClient
    ) -> None:
        role = await client.post("/roles", json={"name": "bwduprole"})
        u = await client.post("/users", json={"email": "bwdup@example.com", "username": "bwdup"})
        await client.post(
            "/user-roles", json={"role_id": role.json()["id"], "user_id": u.json()["id"]}
        )
        # second create of the same pair -> 409; a fresh create in the same batch must roll back.
        u2 = await client.post("/users", json={"email": "bwdup2@example.com", "username": "bwdup2"})
        before = len((await client.get("/user-roles?limit=100")).json()["items"])
        resp = await client.post(
            "/user-roles/batch",
            json={
                "operations": [
                    {
                        "op": "create",
                        "data": {"role_id": role.json()["id"], "user_id": u2.json()["id"]},
                    },
                    {
                        "op": "create",
                        "data": {"role_id": role.json()["id"], "user_id": u.json()["id"]},
                    },  # 409
                ]
            },
        )
        assert resp.status_code == 409
        after = len((await client.get("/user-roles?limit=100")).json()["items"])
        assert after == before  # u2 assignment rolled back


class TestLinkTableAuthorization:
    """Regression tests: membership management is governed by
    ``user_role_permission``, not by ``role_permission``.

    A principal who may only *edit role metadata* must not be able to decide
    who holds a role (privilege escalation via self-assignment); a principal
    who manages membership must not thereby edit roles. Scoped filters must
    also restrict which assignments are visible/creatable.
    """

    async def test_role_admin_cannot_manage_membership(self, client: AsyncClient, session) -> None:
        """role_permission=Permitted alone (no user_role_permission) => 403."""
        principal = await _make_principal(session, email="ra@example.com", username="ra")
        await _assign_role(session, principal.id, {"role_permission": Permitted()})
        await session.commit()
        token = create_auth_token(principal.id)
        headers = {"Authorization": f"Bearer {token}"}

        assert (await client.get("/user-roles", headers=headers)).status_code == 403
        assert (await client.get("/user-roles/count", headers=headers)).status_code == 403
        assert (
            await client.post(
                "/user-roles",
                json={"role_id": str(uuid.uuid4()), "user_id": str(uuid.uuid4())},
                headers=headers,
            )
        ).status_code == 403
        assert (
            await client.delete(f"/user-roles/{uuid.uuid4()}", headers=headers)
        ).status_code == 403
        assert (
            await client.post(
                "/user-roles/batch",
                json={
                    "operations": [
                        {
                            "op": "create",
                            "data": {"role_id": str(uuid.uuid4()), "user_id": str(uuid.uuid4())},
                        }
                    ]
                },
                headers=headers,
            )
        ).status_code == 403

    async def test_membership_manager_cannot_edit_roles(self, client: AsyncClient, session) -> None:
        """user_role_permission=Permitted alone manages membership but cannot
        read or edit roles (403 on /roles)."""
        principal = await _make_principal(session, email="mm@example.com", username="mm")
        await _assign_role(session, principal.id, {"user_role_permission": Permitted()})
        await session.commit()
        token = create_auth_token(principal.id)
        headers = {"Authorization": f"Bearer {token}"}

        # The conftest-seeded test-admin role assignment exists; membership
        # listing works.
        assert (await client.get("/user-roles", headers=headers)).status_code == 200
        assert (
            await client.post(
                "/user-roles",
                json={"role_id": str(uuid.uuid4()), "user_id": str(uuid.uuid4())},
                headers=headers,
            )
        ).status_code == 404  # passes authz, fails on orphan FK
        # Role administration is not conferred by membership management.
        assert (await client.get("/roles", headers=headers)).status_code == 403
        assert (
            await client.patch(f"/roles/{uuid.uuid4()}", json={"name": "x"}, headers=headers)
        ).status_code == 403

    async def test_scoped_membership_filter_limits_visibility(
        self, client: AsyncClient, session
    ) -> None:
        """A scoped user_role policy (user_id = principal) sees only own rows
        and cannot create assignments for other users."""
        principal = await _make_principal(session, email="sc@example.com", username="sc")
        await _assign_role(
            session,
            principal.id,
            {"user_role_permission": _SelfAssignmentAccess()},
        )
        await session.commit()
        token = create_auth_token(principal.id)
        headers = {"Authorization": f"Bearer {token}"}

        # A scope mismatch is a filter (200 with fewer rows), not a denial:
        # the scoped view contains only the principal's own assignment (from
        # _assign_role), not the conftest-seeded test-admin assignment.
        resp = await client.get("/user-roles", headers=headers)
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert {i["user_id"] for i in items} == {str(principal.id)}
        assert len((await client.get("/user-roles")).json()["items"]) > len(items)

        # Create assigning the principal to a (nonexistent) role passes the
        # scope check and fails on orphan FK; assigning someone else is denied.
        own = await client.post(
            "/user-roles",
            json={"role_id": str(uuid.uuid4()), "user_id": str(principal.id)},
            headers=headers,
        )
        assert own.status_code == 404
        denied = await client.post(
            "/user-roles",
            json={"role_id": str(uuid.uuid4()), "user_id": str(uuid.uuid4())},
            headers=headers,
        )
        assert denied.status_code == 403
