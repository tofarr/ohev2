"""Route tests for the ``/secret-values`` reveal projection.

The reveal surface is gated by a **single** USE permission on the parent
provider (AGENTS.md §12). Only a principal with that permission can read
decrypted plaintext.
"""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from tests.unit._auth_helpers import assign_role as _assign_role
from tests.unit._auth_helpers import make_principal as _make_principal

from openhands.ev2.security.security_models import Permitted, ReadOnly
from openhands.ev2.util.auth_token import create_auth_token


async def _seed_provider_and_secret(client: AsyncClient) -> dict[str, object]:
    """Create a static provider plus one static secret via the HTTP API."""
    provider_resp = await client.post("/secret-providers", json={"kind": "static", "data": {}})
    assert provider_resp.status_code == 201, provider_resp.text
    provider = provider_resp.json()

    secret_resp = await client.post(
        "/static-secrets", json={"name": "E2E_TOKEN", "value": "super-secret-value"}
    )
    assert secret_resp.status_code == 201, secret_resp.text
    secret = secret_resp.json()
    return {"provider": provider, "secret": secret}


def _composite(provider_id: str, secret_id: str) -> str:
    return f"{provider_id}/{secret_id}"


class _ProbeClient:
    """A fake provider client with an ``aclose`` hook for cache teardown."""

    def __init__(self) -> None:
        self.closed = False

    async def aclose(self) -> None:
        self.closed = True


class TestSecretValueRoutes:
    async def test_reveal_requires_use(self, client: AsyncClient, session) -> None:
        seeded = await _seed_provider_and_secret(client)
        provider = seeded["provider"]
        secret = seeded["secret"]
        composite = _composite(provider["id"], secret["id"])

        # The admin (all permissions) can reveal.
        reveal = await client.get(f"/secret-values/{composite}")
        assert reveal.status_code == 200, reveal.text
        body = reveal.json()
        assert body["id"] == composite
        assert body["name"] == "E2E_TOKEN"
        assert body["value"] == "super-secret-value"

        # A principal with only static-secret CRUD access has no reveal right.
        restricted = await _make_principal(
            session, email="sv-restricted@example.com", username="sv-restricted"
        )
        await _assign_role(
            session,
            restricted.id,
            {"static_secret_permission": ReadOnly()},
            role_name="sv-static-only",
        )
        await session.commit()
        assert (
            await client.get(
                f"/secret-values/{composite}",
                headers={"Authorization": f"Bearer {create_auth_token(restricted.id)}"},
            )
        ).status_code == 403

        # A principal with USE on the provider can reveal.
        user = await _make_principal(session, email="sv-user@example.com", username="sv-user")
        await _assign_role(
            session,
            user.id,
            {"secret_provider_permission": Permitted()},
            role_name="sv-provider-use",
        )
        await session.commit()
        reveal_user = await client.get(
            f"/secret-values/{composite}",
            headers={"Authorization": f"Bearer {create_auth_token(user.id)}"},
        )
        assert reveal_user.status_code == 200, reveal_user.text
        assert reveal_user.json()["value"] == "super-secret-value"

    async def test_missing_and_malformed_ids_404(self, client: AsyncClient) -> None:
        malformed = await client.get("/secret-values/not-a-composite")
        assert malformed.status_code == 404

        missing = await client.get(f"/secret-values/{uuid.uuid4()}/nope")
        assert missing.status_code == 404

    async def test_batch_read(self, client: AsyncClient) -> None:
        seeded = await _seed_provider_and_secret(client)
        provider = seeded["provider"]
        secret = seeded["secret"]
        composite = _composite(provider["id"], secret["id"])

        response = await client.get(
            "/secret-values/batch",
            params=[("ids", composite), ("ids", f"{uuid.uuid4()}/missing")],
        )
        assert response.status_code == 200, response.text
        items = response.json()["items"]
        assert items[0] is not None
        assert items[0]["id"] == composite
        assert items[0]["value"] == "super-secret-value"
        assert items[1] is None

        too_many = await client.get(
            "/secret-values/batch",
            params=[("ids", f"{uuid.uuid4()}/x") for _ in range(101)],
        )
        assert too_many.status_code == 422

    async def test_search_by_provider(self, client: AsyncClient) -> None:
        seeded = await _seed_provider_and_secret(client)
        provider = seeded["provider"]
        composite = _composite(provider["id"], seeded["secret"]["id"])

        response = await client.get(
            "/secret-values",
            params={"provider_id": provider["id"], "limit": 10},
        )
        assert response.status_code == 200, response.text
        items = response.json()["items"]
        assert len(items) >= 1
        assert composite in [i["id"] for i in items]

    async def test_search_denied_without_use(self, client: AsyncClient, session) -> None:
        seeded = await _seed_provider_and_secret(client)
        provider = seeded["provider"]
        restricted = await _make_principal(
            session, email="sv-search@example.com", username="sv-search"
        )
        await session.commit()
        headers = {"Authorization": f"Bearer {create_auth_token(restricted.id)}"}
        response = await client.get(
            "/secret-values",
            params={"provider_id": provider["id"]},
            headers=headers,
        )
        # The auth dependency fails closed: without USE on the provider the
        # endpoint itself is denied (403), before any existence is revealed.
        assert response.status_code == 403

    async def test_anonymous_denied(self, client: AsyncClient) -> None:
        seeded = await _seed_provider_and_secret(client)
        provider = seeded["provider"]
        composite = _composite(provider["id"], seeded["secret"]["id"])

        # An anonymous caller (no Authorization header) is denied by the USE
        # permission dependency before the handler runs (fail-closed 403).
        from httpx import AsyncClient

        async with AsyncClient(base_url="http://test", transport=client._transport) as anon:
            assert (await anon.get(f"/secret-values/{composite}")).status_code == 403
            assert (
                await anon.get("/secret-values/batch", params={"ids": composite})
            ).status_code == 403
            assert (
                await anon.get("/secret-values", params={"provider_id": provider["id"]})
            ).status_code == 403
