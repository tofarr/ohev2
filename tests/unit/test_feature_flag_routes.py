"""Route tests for the feature_flag feature (DB-backed, ASGI client)."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from tests.unit._auth_helpers import assign_role as _assign_role
from tests.unit._auth_helpers import make_principal as _make_principal

from openhands.ev2.security.security_models import Permitted, ReadOnly
from openhands.ev2.util.auth_token import create_auth_token


async def _seed_role(client: AsyncClient, *, name: str = "ff-role") -> str:
    resp = await client.post("/roles", json={"name": name})
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


class TestCreateFeatureFlagRoute:
    async def test_create_flag(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/feature-flags",
            json={"id": "MY_FLAG", "enabled": True, "description": "desc"},
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["id"] == "MY_FLAG"
        assert body["enabled"] is True
        assert body["description"] == "desc"
        assert body["created_at"] is not None
        assert body["updated_at"] is not None

    async def test_create_flag_defaults(self, client: AsyncClient) -> None:
        resp = await client.post("/feature-flags", json={"id": "DEFAULT_FLAG"})
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["enabled"] is False
        assert body["description"] is None

    async def test_create_duplicate_id_returns_409(self, client: AsyncClient) -> None:
        await client.post("/feature-flags", json={"id": "DUP_FLAG"})
        resp = await client.post("/feature-flags", json={"id": "DUP_FLAG"})
        assert resp.status_code == 409

    async def test_create_invalid_id_charset_returns_422(self, client: AsyncClient) -> None:
        # lowercase rejected
        resp = await client.post("/feature-flags", json={"id": "lower_case"})
        assert resp.status_code == 422
        # hyphen rejected
        resp = await client.post("/feature-flags", json={"id": "HAS-HYPHEN"})
        assert resp.status_code == 422
        # empty rejected
        resp = await client.post("/feature-flags", json={"id": ""})
        assert resp.status_code == 422

    async def test_create_valid_id_with_digits_and_underscores(self, client: AsyncClient) -> None:
        resp = await client.post("/feature-flags", json={"id": "FLAG_2_V3"})
        assert resp.status_code == 201
        assert resp.json()["id"] == "FLAG_2_V3"


class TestGetFeatureFlagRoute:
    async def test_get_existing(self, client: AsyncClient) -> None:
        await client.post("/feature-flags", json={"id": "GET_ME"})
        resp = await client.get("/feature-flags/GET_ME")
        assert resp.status_code == 200
        assert resp.json()["id"] == "GET_ME"

    async def test_get_missing_returns_404(self, client: AsyncClient) -> None:
        resp = await client.get("/feature-flags/NOPE")
        assert resp.status_code == 404


class TestUpdateFeatureFlagRoute:
    async def test_update_enabled_and_description(self, client: AsyncClient) -> None:
        await client.post("/feature-flags", json={"id": "UPD_ME", "enabled": False})
        resp = await client.patch(
            "/feature-flags/UPD_ME",
            json={"enabled": True, "description": "now on"},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["enabled"] is True
        assert body["description"] == "now on"

    async def test_update_missing_returns_404(self, client: AsyncClient) -> None:
        resp = await client.patch("/feature-flags/NOPE", json={"enabled": True})
        assert resp.status_code == 404


class TestDeleteFeatureFlagRoute:
    async def test_delete_flag(self, client: AsyncClient) -> None:
        await client.post("/feature-flags", json={"id": "DEL_ME"})
        resp = await client.delete("/feature-flags/DEL_ME")
        assert resp.status_code == 204
        assert (await client.get("/feature-flags/DEL_ME")).status_code == 404

    async def test_delete_missing_returns_404(self, client: AsyncClient) -> None:
        resp = await client.delete("/feature-flags/NOPE")
        assert resp.status_code == 404

    async def test_delete_flag_cascades_overrides(self, client: AsyncClient) -> None:
        flag_id = "CASC_FLAG"
        role_id = await _seed_role(client, name="casc-role")
        await client.post("/feature-flags", json={"id": flag_id})
        create = await client.post(
            "/feature-flag-roles",
            json={"feature_flag_id": flag_id, "role_id": role_id},
        )
        assert create.status_code == 201
        override_id = create.json()["id"]
        await client.delete(f"/feature-flags/{flag_id}")
        assert (await client.get(f"/feature-flag-roles/{override_id}")).status_code == 404


class TestListFeatureFlagsRoute:
    async def test_search_empty(self, client: AsyncClient) -> None:
        resp = await client.get("/feature-flags")
        assert resp.status_code == 200
        body = resp.json()
        assert body["items"] == []
        assert body["next_cursor"] is None
        assert body["limit"] == 50

    async def test_search_with_limit_and_pagination(self, client: AsyncClient) -> None:
        for i in range(4):
            await client.post("/feature-flags", json={"id": f"PAGE_{i}"})
        resp1 = await client.get("/feature-flags?limit=2")
        body1 = resp1.json()
        assert len(body1["items"]) == 2
        assert body1["next_cursor"] is not None
        resp2 = await client.get(f"/feature-flags?limit=2&cursor={body1['next_cursor']}")
        assert resp2.status_code == 200
        assert len(resp2.json()["items"]) == 2

    async def test_search_invalid_cursor_returns_400(self, client: AsyncClient) -> None:
        resp = await client.get("/feature-flags?cursor=")
        assert resp.status_code == 400

    async def test_search_enabled_filter(self, client: AsyncClient) -> None:
        await client.post("/feature-flags", json={"id": "ON_FLAG", "enabled": True})
        await client.post("/feature-flags", json={"id": "OFF_FLAG", "enabled": False})
        resp = await client.get("/feature-flags?enabled__eq=true")
        items = resp.json()["items"]
        assert all(i["enabled"] is True for i in items)
        assert any(i["id"] == "ON_FLAG" for i in items)

    async def test_search_id_contains_filter(self, client: AsyncClient) -> None:
        await client.post("/feature-flags", json={"id": "ALPHA_1"})
        await client.post("/feature-flags", json={"id": "BETA_2"})
        resp = await client.get("/feature-flags?id__contains=ALPHA")
        items = resp.json()["items"]
        assert all("ALPHA" in i["id"] for i in items)


class TestCountFeatureFlagsRoute:
    async def test_count_after_create(self, client: AsyncClient) -> None:
        await client.post("/feature-flags", json={"id": "CNT_A"})
        await client.post("/feature-flags", json={"id": "CNT_B"})
        resp = await client.get("/feature-flags/count")
        assert resp.status_code == 200
        assert resp.json()["count"] >= 2


class TestFeatureFlagBatchRead:
    async def test_batch_aligned_with_nulls_for_missing(self, client: AsyncClient) -> None:
        await client.post("/feature-flags", json={"id": "BR_A"})
        resp = await client.get("/feature-flags/batch?ids=BR_A&ids=NOPE")
        assert resp.status_code == 200, resp.text
        items = resp.json()["items"]
        assert len(items) == 2
        assert items[0]["id"] == "BR_A"
        assert items[1] is None

    async def test_batch_empty_ids(self, client: AsyncClient) -> None:
        resp = await client.get("/feature-flags/batch")
        assert resp.status_code == 200
        assert resp.json()["items"] == []

    async def test_batch_over_100_returns_422(self, client: AsyncClient) -> None:
        ids = "&".join(f"ids={i}" for i in range(101))
        resp = await client.get(f"/feature-flags/batch?{ids}")
        assert resp.status_code == 422


class TestFeatureFlagBatchWrite:
    async def test_batch_mix_cud_returns_positional(self, client: AsyncClient) -> None:
        await client.post("/feature-flags", json={"id": "BW_A"})
        resp = await client.post(
            "/feature-flags/batch",
            json={
                "operations": [
                    {"op": "create", "data": {"id": "BW_B", "enabled": True}},
                    {"op": "update", "id": "BW_A", "data": {"enabled": True}},
                    {"op": "delete", "id": "BW_A"},
                ]
            },
        )
        assert resp.status_code == 200, resp.text
        items = resp.json()["items"]
        assert len(items) == 3
        assert items[0]["id"] == "BW_B"
        assert items[1]["id"] == "BW_A"
        assert items[2] is None
        # BW_A deleted
        assert (await client.get("/feature-flags/BW_A")).status_code == 404

    async def test_batch_atomic_rollback_on_missing_id(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/feature-flags/batch",
            json={
                "operations": [
                    {"op": "create", "data": {"id": "RB_A"}},
                    {"op": "delete", "id": "MISSING_FLAG"},  # 404
                ]
            },
        )
        assert resp.status_code == 404
        # create rolled back
        assert (await client.get("/feature-flags/RB_A")).status_code == 404

    async def test_batch_empty_ops_rejected(self, client: AsyncClient) -> None:
        resp = await client.post("/feature-flags/batch", json={"operations": []})
        assert resp.status_code == 422

    async def test_batch_over_100_ops_rejected(self, client: AsyncClient) -> None:
        ops = [{"op": "delete", "id": f"X_{i}"} for i in range(101)]
        resp = await client.post("/feature-flags/batch", json={"operations": ops})
        assert resp.status_code == 422


# ---------------------------------------------------------------------- #
# Feature flag role overrides
# ---------------------------------------------------------------------- #


class TestCreateFeatureFlagRoleRoute:
    async def test_create_override(self, client: AsyncClient) -> None:
        flag_id = "OVR_FLAG"
        role_id = await _seed_role(client, name="ovr-role")
        await client.post("/feature-flags", json={"id": flag_id})
        resp = await client.post(
            "/feature-flag-roles",
            json={"feature_flag_id": flag_id, "role_id": role_id},
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["feature_flag_id"] == flag_id
        assert body["role_id"] == role_id
        assert "id" in body
        assert "created_at" in body

    async def test_create_duplicate_returns_409(self, client: AsyncClient) -> None:
        flag_id = "DUP_OVR_FLAG"
        role_id = await _seed_role(client, name="dup-ovr-role")
        await client.post("/feature-flags", json={"id": flag_id})
        payload = {"feature_flag_id": flag_id, "role_id": role_id}
        first = await client.post("/feature-flag-roles", json=payload)
        assert first.status_code == 201
        second = await client.post("/feature-flag-roles", json=payload)
        assert second.status_code == 409

    async def test_create_missing_flag_returns_404(self, client: AsyncClient) -> None:
        role_id = await _seed_role(client, name="orphan-role")
        resp = await client.post(
            "/feature-flag-roles",
            json={"feature_flag_id": "NO_SUCH_FLAG", "role_id": role_id},
        )
        assert resp.status_code == 404

    async def test_create_missing_role_returns_404(self, client: AsyncClient) -> None:
        await client.post("/feature-flags", json={"id": "ORPHAN_FLAG"})
        resp = await client.post(
            "/feature-flag-roles",
            json={"feature_flag_id": "ORPHAN_FLAG", "role_id": str(uuid.uuid4())},
        )
        assert resp.status_code == 404


class TestGetFeatureFlagRoleRoute:
    async def test_get_existing(self, client: AsyncClient) -> None:
        flag_id = "GET_OVR_FLAG"
        role_id = await _seed_role(client, name="get-ovr-role")
        await client.post("/feature-flags", json={"id": flag_id})
        create = await client.post(
            "/feature-flag-roles",
            json={"feature_flag_id": flag_id, "role_id": role_id},
        )
        lid = create.json()["id"]
        resp = await client.get(f"/feature-flag-roles/{lid}")
        assert resp.status_code == 200
        assert resp.json()["id"] == lid

    async def test_get_missing_returns_404(self, client: AsyncClient) -> None:
        resp = await client.get(f"/feature-flag-roles/{uuid.uuid4()}")
        assert resp.status_code == 404


class TestListFeatureFlagRolesRoute:
    async def test_search_with_limit(self, client: AsyncClient) -> None:
        flag_id = "LIST_OVR_FLAG"
        await client.post("/feature-flags", json={"id": flag_id})
        for i in range(3):
            role_id = await _seed_role(client, name=f"list-ovr-role-{i}")
            await client.post(
                "/feature-flag-roles",
                json={"feature_flag_id": flag_id, "role_id": role_id},
            )
        resp = await client.get("/feature-flag-roles?limit=2")
        body = resp.json()
        assert len(body["items"]) == 2
        assert body["next_cursor"] is not None

    async def test_search_invalid_cursor_returns_400(self, client: AsyncClient) -> None:
        resp = await client.get("/feature-flag-roles?cursor=not-a-uuid")
        assert resp.status_code == 400

    async def test_search_feature_flag_id_filter(self, client: AsyncClient) -> None:
        await client.post("/feature-flags", json={"id": "FILTER_A"})
        await client.post("/feature-flags", json={"id": "FILTER_B"})
        role_id = await _seed_role(client, name="filter-role")
        await client.post(
            "/feature-flag-roles",
            json={"feature_flag_id": "FILTER_A", "role_id": role_id},
        )
        await client.post(
            "/feature-flag-roles",
            json={"feature_flag_id": "FILTER_B", "role_id": role_id},
        )
        resp = await client.get("/feature-flag-roles?feature_flag_id__eq=FILTER_A")
        items = resp.json()["items"]
        assert all(i["feature_flag_id"] == "FILTER_A" for i in items)


class TestCountFeatureFlagRolesRoute:
    async def test_count_after_create(self, client: AsyncClient) -> None:
        flag_id = "CNT_OVR_FLAG"
        role_id = await _seed_role(client, name="cnt-ovr-role")
        await client.post("/feature-flags", json={"id": flag_id})
        await client.post(
            "/feature-flag-roles",
            json={"feature_flag_id": flag_id, "role_id": role_id},
        )
        resp = await client.get("/feature-flag-roles/count")
        assert resp.status_code == 200
        assert resp.json()["count"] >= 1


class TestFeatureFlagRoleBatchRead:
    async def test_batch_aligned_with_nulls(self, client: AsyncClient) -> None:
        flag_id = "BR_OVR_FLAG"
        role_id = await _seed_role(client, name="br-ovr-role")
        await client.post("/feature-flags", json={"id": flag_id})
        create = await client.post(
            "/feature-flag-roles",
            json={"feature_flag_id": flag_id, "role_id": role_id},
        )
        aid = create.json()["id"]
        missing = str(uuid.uuid4())
        resp = await client.get(f"/feature-flag-roles/batch?ids={aid}&ids={missing}")
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 2
        assert items[0]["id"] == aid
        assert items[1] is None


class TestFeatureFlagRoleBatchWrite:
    async def test_batch_mix_cd_returns_positional(self, client: AsyncClient) -> None:
        flag_id = "BW_OVR_FLAG"
        role_a = await _seed_role(client, name="bw-ovr-role-a")
        role_b = await _seed_role(client, name="bw-ovr-role-b")
        await client.post("/feature-flags", json={"id": flag_id})
        a = await client.post(
            "/feature-flag-roles",
            json={"feature_flag_id": flag_id, "role_id": role_a},
        )
        resp = await client.post(
            "/feature-flag-roles/batch",
            json={
                "operations": [
                    {"op": "delete", "id": a.json()["id"]},
                    {
                        "op": "create",
                        "data": {"feature_flag_id": flag_id, "role_id": role_b},
                    },
                ]
            },
        )
        assert resp.status_code == 200, resp.text
        items = resp.json()["items"]
        assert len(items) == 2
        assert items[0] is None
        assert items[1]["role_id"] == role_b
        assert (await client.get(f"/feature-flag-roles/{a.json()['id']}")).status_code == 404

    async def test_batch_atomic_rollback_on_missing_id(self, client: AsyncClient) -> None:
        flag_id = "RB_OVR_FLAG"
        role_id = await _seed_role(client, name="rb-ovr-role")
        await client.post("/feature-flags", json={"id": flag_id})
        resp = await client.post(
            "/feature-flag-roles/batch",
            json={
                "operations": [
                    {
                        "op": "create",
                        "data": {"feature_flag_id": flag_id, "role_id": role_id},
                    },
                    {"op": "delete", "id": str(uuid.uuid4())},  # 404
                ]
            },
        )
        assert resp.status_code == 404
        # create rolled back
        items = (await client.get("/feature-flag-roles?limit=100")).json()["items"]
        assert not any(i["role_id"] == role_id for i in items)

    async def test_batch_update_op_rejected(self, client: AsyncClient) -> None:
        # overrides are immutable; update op must be rejected by the discriminated union.
        resp = await client.post(
            "/feature-flag-roles/batch",
            json={"operations": [{"op": "update", "id": str(uuid.uuid4()), "data": {}}]},
        )
        assert resp.status_code == 422


class TestDeleteFeatureFlagRoleRoute:
    async def test_delete_override(self, client: AsyncClient) -> None:
        flag_id = "DEL_OVR_FLAG"
        role_id = await _seed_role(client, name="del-ovr-role")
        await client.post("/feature-flags", json={"id": flag_id})
        create = await client.post(
            "/feature-flag-roles",
            json={"feature_flag_id": flag_id, "role_id": role_id},
        )
        lid = create.json()["id"]
        resp = await client.delete(f"/feature-flag-roles/{lid}")
        assert resp.status_code == 204
        assert (await client.get(f"/feature-flag-roles/{lid}")).status_code == 404

    async def test_delete_missing_returns_404(self, client: AsyncClient) -> None:
        resp = await client.delete(f"/feature-flag-roles/{uuid.uuid4()}")
        assert resp.status_code == 404


class TestPermissionEnforcement:
    """The feature_flag and feature_flag_role resources are governed by their
    own role permission columns."""

    async def test_missing_auth_token_anonymous_denied(self, app) -> None:
        from httpx import ASGITransport, AsyncClient

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            resp = await ac.get("/feature-flags")
        assert resp.status_code == 403

    async def test_invalid_auth_token_returns_401(self, client: AsyncClient) -> None:
        resp = await client.get("/feature-flags", headers={"X-API-Key": "not-a-valid-token"})
        assert resp.status_code == 401

    async def test_readonly_role_allows_read_denies_write(
        self, client: AsyncClient, session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        principal = await _make_principal(session, email="ro@example.com", username="ro")
        await _assign_role(session, principal.id, {"feature_flag_permission": ReadOnly()})
        await session.commit()

        token = create_auth_token(principal.id)
        resp = await client.get("/feature-flags", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        # Create requires CREATE; ReadOnly denies it.
        resp = await client.post(
            "/feature-flags",
            json={"id": "RO_FLAG"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403

    async def test_permitted_role_allows_write(
        self, client: AsyncClient, session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        principal = await _make_principal(session, email="perm@example.com", username="perm")
        await _assign_role(
            session,
            principal.id,
            {"feature_flag_permission": Permitted(), "feature_flag_role_permission": Permitted()},
        )
        await session.commit()

        token = create_auth_token(principal.id)
        resp = await client.get("/feature-flags", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        resp = await client.post(
            "/feature-flags",
            json={"id": "PERM_FLAG"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 201

    async def test_feature_flag_role_permission_governs_overrides(
        self, client: AsyncClient, session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        principal = await _make_principal(session, email="ovr@example.com", username="ovr")
        # Only feature_flag_role permission granted (read-only on feature_flag).
        await _assign_role(
            session,
            principal.id,
            {"feature_flag_permission": ReadOnly(), "feature_flag_role_permission": Permitted()},
        )
        await session.commit()

        token = create_auth_token(principal.id)
        resp = await client.get("/feature-flag-roles", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200


class TestGetEnabledFeatureFlags:
    """``GET /feature-flags/enabled`` returns the flags enabled for the current
    user (globally enabled OR overridden on via a role the user holds)."""

    async def test_anonymous_denied_401(self, app) -> None:
        from httpx import ASGITransport, AsyncClient

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            resp = await ac.get("/feature-flags/enabled")
        assert resp.status_code == 401

    async def test_returns_globally_enabled_flags(self, client: AsyncClient, session) -> None:
        principal = await _make_principal(session, email="ge@example.com", username="ge")
        await session.commit()
        token = create_auth_token(principal.id)

        # Seed flags via the admin client: two enabled, one disabled.
        await client.post("/feature-flags", json={"id": "ON_A", "enabled": True})
        await client.post("/feature-flags", json={"id": "ON_B", "enabled": True})
        await client.post("/feature-flags", json={"id": "OFF_C", "enabled": False})

        resp = await client.get(
            "/feature-flags/enabled", headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 200, resp.text
        flags = set(resp.json()["flags"])
        assert flags == {"ON_A", "ON_B"}

    async def test_override_enables_flag_for_role_holder(
        self, client: AsyncClient, session
    ) -> None:
        principal = await _make_principal(session, email="ov@example.com", username="ov")
        # Grant a role whose override will flip a globally-disabled flag on.
        role = await _assign_role(
            session,
            principal.id,
            {"feature_flag_permission": ReadOnly()},
            role_name="ov-role",
        )
        await session.commit()

        # Globally disabled flag + override row attaching the user's role.
        await client.post("/feature-flags", json={"id": "OVERRIDE_ME", "enabled": False})
        await client.post(
            "/feature-flag-roles",
            json={"feature_flag_id": "OVERRIDE_ME", "role_id": str(role.id)},
        )
        # A globally-enabled flag is also present.
        await client.post("/feature-flags", json={"id": "GLOBAL_ON", "enabled": True})

        token = create_auth_token(principal.id)
        resp = await client.get(
            "/feature-flags/enabled", headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 200, resp.text
        flags = set(resp.json()["flags"])
        # Override flips the disabled flag on; the global one stays on too.
        assert "OVERRIDE_ME" in flags
        assert "GLOBAL_ON" in flags

    async def test_override_does_not_leak_to_user_without_role(
        self, client: AsyncClient, session
    ) -> None:
        # User A holds the role; user B does not.
        principal_a = await _make_principal(session, email="a@example.com", username="a")
        principal_b = await _make_principal(session, email="b@example.com", username="b")
        role = await _assign_role(
            session,
            principal_a.id,
            {"feature_flag_permission": ReadOnly()},
            role_name="a-role",
        )
        await session.commit()

        await client.post("/feature-flags", json={"id": "ONLY_FOR_A", "enabled": False})
        await client.post(
            "/feature-flag-roles",
            json={"feature_flag_id": "ONLY_FOR_A", "role_id": str(role.id)},
        )

        token_b = create_auth_token(principal_b.id)
        resp = await client.get(
            "/feature-flags/enabled", headers={"Authorization": f"Bearer {token_b}"}
        )
        assert resp.status_code == 200
        assert "ONLY_FOR_A" not in resp.json()["flags"]

    async def test_no_flags_returns_empty_list(self, client: AsyncClient, session) -> None:
        principal = await _make_principal(session, email="nf@example.com", username="nf")
        await session.commit()
        token = create_auth_token(principal.id)

        resp = await client.get(
            "/feature-flags/enabled", headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 200
        assert resp.json()["flags"] == []

    async def test_enabled_path_not_shadowed_by_flag_id(self, client: AsyncClient) -> None:
        """A flag literally named ``ENABLED`` must not shadow the ``/enabled``
        route (static path must match before the ``/{flag_id}`` param)."""
        await client.post("/feature-flags", json={"id": "ENABLED", "enabled": True})
        resp = await client.get("/feature-flags/enabled")
        # The route handler runs, returning the EnabledFeatureFlags shape — not
        # the single FeatureFlagRead for the "ENABLED" flag.
        assert resp.status_code == 200
        assert "flags" in resp.json()
