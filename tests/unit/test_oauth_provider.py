"""Unit tests for the governed ``OAuthProvider`` CRUD resource (sub-issue #143)."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
class TestOAuthProviderCRUD:
    async def test_create_and_read(self, client: AsyncClient) -> None:
        payload = {
            "name": "github",
            "url": "https://github.com/login/oauth",
            "client_id": "cid123",
            "client_secret": "secret456",
            "scopes": ["repo", "user"],
        }
        resp = await client.post("/oauth/providers", json=payload)
        assert resp.status_code == 201
        body = resp.json()
        assert body["name"] == "github"
        assert body["client_id"] == "cid123"
        assert body["client_secret"] == "**********"
        assert body["scopes"] == ["repo", "user"]
        assert body["enabled"] is True
        provider_id = body["id"]

        get_resp = await client.get(f"/oauth/providers/{provider_id}")
        assert get_resp.status_code == 200
        assert get_resp.json()["id"] == provider_id

    async def test_create_duplicate_name_conflict(self, client: AsyncClient) -> None:
        payload = {
            "name": "gitlab",
            "url": "https://gitlab.com/oauth",
            "client_id": "cid",
            "client_secret": "sec",
        }
        resp1 = await client.post("/oauth/providers", json=payload)
        assert resp1.status_code == 201
        resp2 = await client.post("/oauth/providers", json=payload)
        assert resp2.status_code == 409

    async def test_update_provider(self, client: AsyncClient) -> None:
        create_resp = await client.post(
            "/oauth/providers",
            json={
                "name": "bitbucket",
                "url": "https://bitbucket.org/oauth",
                "client_id": "cid",
                "client_secret": "sec",
            },
        )
        assert create_resp.status_code == 201
        provider_id = create_resp.json()["id"]

        update_resp = await client.patch(
            f"/oauth/providers/{provider_id}",
            json={"enabled": False, "url": "https://bitbucket.org/site/oauth2"},
        )
        assert update_resp.status_code == 200
        body = update_resp.json()
        assert body["enabled"] is False
        assert body["url"] == "https://bitbucket.org/site/oauth2"

    async def test_delete_provider(self, client: AsyncClient) -> None:
        create_resp = await client.post(
            "/oauth/providers",
            json={
                "name": "jira",
                "url": "https://atlassian.net/oauth",
                "client_id": "cid",
                "client_secret": "sec",
            },
        )
        provider_id = create_resp.json()["id"]
        del_resp = await client.delete(f"/oauth/providers/{provider_id}")
        assert del_resp.status_code == 204
        get_resp = await client.get(f"/oauth/providers/{provider_id}")
        assert get_resp.status_code == 404

    async def test_get_not_found(self, client: AsyncClient) -> None:
        resp = await client.get(f"/oauth/providers/{uuid.uuid4()}")
        assert resp.status_code == 404

    async def test_search_providers(self, client: AsyncClient) -> None:
        for i in range(3):
            await client.post(
                "/oauth/providers",
                json={
                    "name": f"provider-{i}",
                    "url": f"https://example-{i}.com",
                    "client_id": f"cid-{i}",
                    "client_secret": f"sec-{i}",
                },
            )
        resp = await client.get("/oauth/providers")
        assert resp.status_code == 200
        body = resp.json()
        assert len(body["items"]) >= 3

    async def test_batch_read(self, client: AsyncClient) -> None:
        ids = []
        for i in range(3):
            resp = await client.post(
                "/oauth/providers",
                json={
                    "name": f"batch-{i}",
                    "url": f"https://batch-{i}.com",
                    "client_id": f"cid-{i}",
                    "client_secret": f"sec-{i}",
                },
            )
            ids.append(resp.json()["id"])
        batch_resp = await client.get(
            "/oauth/providers/batch",
            params=[("ids", i) for i in ids],
        )
        assert batch_resp.status_code == 200
        body = batch_resp.json()
        assert len(body["items"]) == 3
        for item in body["items"]:
            assert item is not None

    async def test_count(self, client: AsyncClient) -> None:
        resp = await client.get("/oauth/providers/count")
        assert resp.status_code == 200
        assert resp.json()["count"] >= 0

    async def test_client_secret_not_exposed_in_read(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/oauth/providers",
            json={
                "name": "secret-check",
                "url": "https://secret.example.com",
                "client_id": "cid",
                "client_secret": "super-secret-value",
            },
        )
        body = resp.json()
        assert body["client_secret"] == "**********"
