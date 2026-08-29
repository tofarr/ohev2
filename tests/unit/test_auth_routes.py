"""Route tests for the federated OAuth (auth) feature (DB-backed, ASGI client)."""

from __future__ import annotations

import base64
import json
import uuid
from urllib.parse import parse_qs, urlparse

import httpx
import respx
from httpx import ASGITransport, AsyncClient

_IDP_BASE = "https://idp.example.com"


def _make_id_token(sub: str, email: str) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=").decode()
    payload = (
        base64.urlsafe_b64encode(json.dumps({"sub": sub, "email": email}).encode())
        .rstrip(b"=")
        .decode()
    )
    return f"{header}.{payload}."


def _idp_token_response(sub: str, email: str, refresh: str = "idp-refresh-1") -> dict:
    return {
        "access_token": "idp-access-1",
        "refresh_token": refresh,
        "expires_in": 3600,
        "id_token": _make_id_token(sub, email),
        "token_type": "Bearer",
    }


class TestOAuthClientCrud:
    async def test_create_and_get_client(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/auth/clients",
            json={
                "client_id": "route-client-1",
                "client_secret": "s3cr3t",
                "name": "Route Client",
                "redirect_uris": ["https://app.example.com/cb"],
            },
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["client_id"] == "route-client-1"
        assert body["name"] == "Route Client"
        assert body["redirect_uris"] == ["https://app.example.com/cb"]
        assert body["enabled"] is True
        assert "client_secret" not in body
        cid = body["id"]

        got = await client.get(f"/auth/clients/{cid}")
        assert got.status_code == 200
        assert got.json()["client_id"] == "route-client-1"

    async def test_get_missing_returns_404(self, client: AsyncClient) -> None:
        resp = await client.get(f"/auth/clients/{uuid.uuid4()}")
        assert resp.status_code == 404

    async def test_search_clients(self, client: AsyncClient) -> None:
        for i in range(3):
            await client.post(
                "/auth/clients",
                json={
                    "client_id": f"search-{i}",
                    "client_secret": "s",
                    "redirect_uris": [],
                },
            )
        resp = await client.get("/auth/clients", params={"limit": 2})
        assert resp.status_code == 200
        body = resp.json()
        assert len(body["items"]) == 2
        assert body["next_cursor"] is not None

    async def test_update_client(self, client: AsyncClient) -> None:
        create = await client.post(
            "/auth/clients",
            json={
                "client_id": "upd-1",
                "client_secret": "s",
                "redirect_uris": ["https://a/cb"],
            },
        )
        cid = create.json()["id"]
        resp = await client.patch(
            f"/auth/clients/{cid}",
            json={"name": "Renamed", "enabled": False, "redirect_uris": ["https://b/cb"]},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["name"] == "Renamed"
        assert body["enabled"] is False
        assert body["redirect_uris"] == ["https://b/cb"]

    async def test_delete_client(self, client: AsyncClient) -> None:
        create = await client.post(
            "/auth/clients",
            json={"client_id": "del-1", "client_secret": "s", "redirect_uris": []},
        )
        cid = create.json()["id"]
        resp = await client.delete(f"/auth/clients/{cid}")
        assert resp.status_code == 204
        assert (await client.get(f"/auth/clients/{cid}")).status_code == 404


class TestBatchClientsRoute:
    async def test_batch_returns_aligned_with_nulls_for_missing(self, client: AsyncClient) -> None:
        a = await client.post(
            "/auth/clients", json={"client_id": "ba", "client_secret": "s", "redirect_uris": []}
        )
        b = await client.post(
            "/auth/clients", json={"client_id": "bb", "client_secret": "s", "redirect_uris": []}
        )
        aid, bid = a.json()["id"], b.json()["id"]
        missing = str(uuid.uuid4())
        resp = await client.get(f"/auth/clients/batch?ids={aid}&ids={missing}&ids={bid}")
        assert resp.status_code == 200, resp.text
        items = resp.json()["items"]
        assert len(items) == 3
        assert items[0]["id"] == aid
        assert items[1] is None
        assert items[2]["id"] == bid

    async def test_batch_empty_ids_returns_empty_list(self, client: AsyncClient) -> None:
        resp = await client.get("/auth/clients/batch")
        assert resp.status_code == 200
        assert resp.json()["items"] == []

    async def test_batch_over_100_ids_returns_422(self, client: AsyncClient) -> None:
        ids = "&".join(f"ids={uuid.uuid4()}" for _ in range(101))
        resp = await client.get(f"/auth/clients/batch?{ids}")
        assert resp.status_code == 422


class TestBatchWriteClients:
    """POST /auth/clients/batch — mix of create/update/delete in one transaction."""

    async def test_batch_mix_cud_returns_positional_results(self, client: AsyncClient) -> None:
        r1 = await client.post(
            "/auth/clients", json={"client_id": "bwr1", "client_secret": "s", "redirect_uris": []}
        )
        r2 = await client.post(
            "/auth/clients", json={"client_id": "bwr2", "client_secret": "s", "redirect_uris": []}
        )
        cid1, cid2 = r1.json()["id"], r2.json()["id"]
        resp = await client.post(
            "/auth/clients/batch",
            json={
                "operations": [
                    {
                        "op": "create",
                        "data": {"client_id": "bwr3", "client_secret": "s", "redirect_uris": []},
                    },
                    {"op": "update", "id": cid1, "data": {"name": "Renamed"}},
                    {"op": "delete", "id": cid2},
                ]
            },
        )
        assert resp.status_code == 200, resp.text
        items = resp.json()["items"]
        assert len(items) == 3
        assert items[0]["client_id"] == "bwr3"
        assert items[1]["id"] == cid1 and items[1]["name"] == "Renamed"
        assert items[2] is None
        assert (await client.get(f"/auth/clients/{cid2}")).status_code == 404

    async def test_batch_atomic_rollback_on_missing_id(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/auth/clients/batch",
            json={
                "operations": [
                    {
                        "op": "create",
                        "data": {
                            "client_id": "bwrollback",
                            "client_secret": "s",
                            "redirect_uris": [],
                        },
                    },
                    {"op": "delete", "id": str(uuid.uuid4())},  # missing -> 404
                ]
            },
        )
        assert resp.status_code == 404
        clients = (await client.get("/auth/clients?limit=100")).json()["items"]
        ids = {c["client_id"] for c in clients}
        assert "bwrollback" not in ids

    async def test_batch_conflict_rolls_back_whole_batch(self, client: AsyncClient) -> None:
        await client.post(
            "/auth/clients",
            json={"client_id": "bwconflict", "client_secret": "s", "redirect_uris": []},
        )
        resp = await client.post(
            "/auth/clients/batch",
            json={
                "operations": [
                    {
                        "op": "create",
                        "data": {"client_id": "bwfresh", "client_secret": "s", "redirect_uris": []},
                    },
                    {
                        "op": "create",
                        "data": {
                            "client_id": "bwconflict",
                            "client_secret": "s",
                            "redirect_uris": [],
                        },
                    },  # 409
                ]
            },
        )
        assert resp.status_code == 409
        clients = (await client.get("/auth/clients?limit=100")).json()["items"]
        ids = {c["client_id"] for c in clients}
        assert "bwfresh" not in ids

    async def test_batch_empty_operations_rejected(self, client: AsyncClient) -> None:
        resp = await client.post("/auth/clients/batch", json={"operations": []})
        assert resp.status_code == 422


class TestAuthorizeRoute:
    async def test_authorize_redirects_to_idp(self, client: AsyncClient) -> None:
        await client.post(
            "/auth/clients",
            json={
                "client_id": "auth-1",
                "client_secret": "s",
                "redirect_uris": ["https://app.example.com/cb"],
            },
        )
        resp = await client.get(
            "/auth/authorize",
            params={
                "response_type": "code",
                "client_id": "auth-1",
                "redirect_uri": "https://app.example.com/cb",
                "state": "xyz",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302
        location = resp.headers["location"]
        assert location.startswith(f"{_IDP_BASE}/authorize?")
        qs = parse_qs(urlparse(location).query)
        assert qs["response_type"] == ["code"]
        assert qs["code_challenge_method"] == ["S256"]

    async def test_authorize_rejects_unlisted_redirect(self, client: AsyncClient) -> None:
        await client.post(
            "/auth/clients",
            json={"client_id": "auth-2", "client_secret": "s", "redirect_uris": ["https://ok/cb"]},
        )
        resp = await client.get(
            "/auth/authorize",
            params={
                "response_type": "code",
                "client_id": "auth-2",
                "redirect_uri": "https://evil/cb",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 400

    async def test_authorize_rejects_unknown_client(self, client: AsyncClient) -> None:
        resp = await client.get(
            "/auth/authorize",
            params={
                "response_type": "code",
                "client_id": "nope",
                "redirect_uri": "https://ok/cb",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 401

    async def test_authorize_rejects_unsupported_response_type(self, client: AsyncClient) -> None:
        # response_type is an OpenAPI enum (Literal["code", "cookie"]); a value
        # outside it is rejected as a validation error (422), not a 400.
        await client.post(
            "/auth/clients",
            json={"client_id": "auth-3", "client_secret": "s", "redirect_uris": ["https://ok/cb"]},
        )
        resp = await client.get(
            "/auth/authorize",
            params={
                "response_type": "token",
                "client_id": "auth-3",
                "redirect_uri": "https://ok/cb",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 422


class TestFullOAuthFlowRoute:
    """End-to-end: authorize → callback → token → refresh via the ASGI client."""

    @respx.mock
    async def test_full_flow(self, app) -> None:
        # The callback URL handed to the IdP is derived from config
        # (OHE_BASE_URL=http://test in the test config).
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            from openhands.ev2.util.auth_token import create_auth_token

            c.headers["X-API-Key"] = create_auth_token(
                uuid.UUID("12345678-1234-5678-1234-456789abcdef")
            )
            await c.post(
                "/auth/clients",
                json={
                    "client_id": "flow-1",
                    "client_secret": "flow-secret",
                    "redirect_uris": ["https://app.example.com/cb"],
                },
            )

            # 1. authorize
            auth = await c.get(
                "/auth/authorize",
                params={
                    "response_type": "code",
                    "client_id": "flow-1",
                    "redirect_uri": "https://app.example.com/cb",
                    "state": "client-state",
                },
                follow_redirects=False,
            )
            assert auth.status_code == 302
            idp_state = parse_qs(urlparse(auth.headers["location"]).query)["state"][0]

            # 2. callback (IdP redirects here with code+state)
            respx.post(f"{_IDP_BASE}/token").mock(
                return_value=httpx.Response(
                    200, json=_idp_token_response("route-sub-1", "route@example.com")
                )
            )
            cb = await c.get(
                "/auth/callback",
                params={"code": "idp-code", "state": idp_state},
                follow_redirects=False,
            )
            assert cb.status_code == 302, cb.text
            cb_location = cb.headers["location"]
            assert cb_location.startswith("https://app.example.com/cb?")
            cb_qs = parse_qs(urlparse(cb_location).query)
            assert cb_qs["state"] == ["client-state"]
            our_code = cb_qs["code"][0]
            # response_type=code: NO session cookie is minted. The client is a
            # confidential (token-based) one that exchanges the code at /token;
            # it must never receive a browser session.
            assert not cb.cookies.get("ohesession")

            # 3. token exchange
            tok = await c.post(
                "/auth/token",
                json={
                    "grant_type": "authorization_code",
                    "code": our_code,
                    "redirect_uri": "https://app.example.com/cb",
                    "client_id": "flow-1",
                    "client_secret": "flow-secret",
                },
            )
            assert tok.status_code == 200, tok.text
            tokens = tok.json()
            assert tokens["access_token"]
            assert tokens["refresh_token"]
            assert tokens["token_type"] == "Bearer"

            # 4. refresh
            respx.post(f"{_IDP_BASE}/token").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "access_token": "idp-access-2",
                        "refresh_token": "idp-refresh-2",
                        "expires_in": 3600,
                        "token_type": "Bearer",
                    },
                )
            )
            ref = await c.post(
                "/auth/refresh",
                json={
                    "grant_type": "refresh_token",
                    "refresh_token": tokens["refresh_token"],
                    "client_id": "flow-1",
                    "client_secret": "flow-secret",
                },
            )
            assert ref.status_code == 200, ref.text
            new_tokens = ref.json()
            assert new_tokens["access_token"] != tokens["access_token"]

    @respx.mock
    async def test_token_wrong_secret_rejected(self, app) -> None:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            from openhands.ev2.util.auth_token import create_auth_token

            c.headers["X-API-Key"] = create_auth_token(
                uuid.UUID("12345678-1234-5678-1234-456789abcdef")
            )
            await c.post(
                "/auth/clients",
                json={
                    "client_id": "flow-2",
                    "client_secret": "right",
                    "redirect_uris": ["https://app.example.com/cb"],
                },
            )
            auth = await c.get(
                "/auth/authorize",
                params={
                    "response_type": "code",
                    "client_id": "flow-2",
                    "redirect_uri": "https://app.example.com/cb",
                },
                follow_redirects=False,
            )
            idp_state = parse_qs(urlparse(auth.headers["location"]).query)["state"][0]
            respx.post(f"{_IDP_BASE}/token").mock(
                return_value=httpx.Response(
                    200, json=_idp_token_response("route-sub-2", "r2@example.com")
                )
            )
            cb = await c.get(
                "/auth/callback",
                params={"code": "idp-code", "state": idp_state},
                follow_redirects=False,
            )
            our_code = parse_qs(urlparse(cb.headers["location"]).query)["code"][0]
            tok = await c.post(
                "/auth/token",
                json={
                    "grant_type": "authorization_code",
                    "code": our_code,
                    "redirect_uri": "https://app.example.com/cb",
                    "client_id": "flow-2",
                    "client_secret": "wrong",
                },
            )
            assert tok.status_code == 401

    @respx.mock
    async def test_cookie_flow_sets_cookie_without_code(self, app) -> None:
        # response_type=cookie: the callback sets a session cookie and returns
        # NO authorization code (the cookie authenticates the browser).
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            from openhands.ev2.util.auth_token import create_auth_token

            c.headers["X-API-Key"] = create_auth_token(
                uuid.UUID("12345678-1234-5678-1234-456789abcdef")
            )
            await c.post(
                "/auth/clients",
                json={
                    "client_id": "cookie-flow",
                    "client_secret": "cookie-secret",
                    "redirect_uris": ["https://app.example.com/cb"],
                },
            )

            auth = await c.get(
                "/auth/authorize",
                params={
                    "response_type": "cookie",
                    "client_id": "cookie-flow",
                    "redirect_uri": "https://app.example.com/cb",
                    "state": "client-state",
                },
                follow_redirects=False,
            )
            assert auth.status_code == 302
            idp_state = parse_qs(urlparse(auth.headers["location"]).query)["state"][0]

            respx.post(f"{_IDP_BASE}/token").mock(
                return_value=httpx.Response(
                    200, json=_idp_token_response("cookie-sub-1", "cookie@example.com")
                )
            )
            cb = await c.get(
                "/auth/callback",
                params={"code": "idp-code", "state": idp_state},
                follow_redirects=False,
            )
            assert cb.status_code == 302, cb.text
            # Redirected to the client redirect URI, but with NO code param.
            cb_location = cb.headers["location"]
            assert cb_location.startswith("https://app.example.com/cb")
            cb_qs = parse_qs(urlparse(cb_location).query)
            assert "code" not in cb_qs
            # The client state is still echoed back.
            assert cb_qs["state"] == ["client-state"]
            # The session cookie is set (the sole credential for this flow).
            assert cb.cookies.get("ohesession")

    @respx.mock
    async def test_revoke_refresh_token_kills_refresh(self, app) -> None:
        """Revoking a refresh token makes the next /auth/refresh fail (400)."""
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            from openhands.ev2.util.auth_token import create_auth_token

            c.headers["X-API-Key"] = create_auth_token(
                uuid.UUID("12345678-1234-5678-1234-456789abcdef")
            )
            await c.post(
                "/auth/clients",
                json={
                    "client_id": "revoke-1",
                    "client_secret": "revoke-secret",
                    "redirect_uris": ["https://app.example.com/cb"],
                },
            )
            respx.post(f"{_IDP_BASE}/token").mock(
                return_value=httpx.Response(
                    200, json=_idp_token_response("rev-sub", "rev@example.com")
                )
            )
            auth = await c.get(
                "/auth/authorize",
                params={
                    "response_type": "code",
                    "client_id": "revoke-1",
                    "redirect_uri": "https://app.example.com/cb",
                },
                follow_redirects=False,
            )
            idp_state = parse_qs(urlparse(auth.headers["location"]).query)["state"][0]
            cb = await c.get(
                "/auth/callback",
                params={"code": "idp-code", "state": idp_state},
                follow_redirects=False,
            )
            our_code = parse_qs(urlparse(cb.headers["location"]).query)["code"][0]
            tok = await c.post(
                "/auth/token",
                json={
                    "grant_type": "authorization_code",
                    "code": our_code,
                    "redirect_uri": "https://app.example.com/cb",
                    "client_id": "revoke-1",
                    "client_secret": "revoke-secret",
                },
            )
            refresh_token = tok.json()["refresh_token"]

            # Revoke the refresh token (form-encoded).
            rev = await c.post(
                "/auth/revoke",
                data={
                    "token": refresh_token,
                    "token_type_hint": "refresh_token",
                    "client_id": "revoke-1",
                    "client_secret": "revoke-secret",
                },
            )
            assert rev.status_code == 200, rev.text

            # The next refresh must fail: the backing row is gone.
            ref = await c.post(
                "/auth/refresh",
                json={
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "client_id": "revoke-1",
                    "client_secret": "revoke-secret",
                },
            )
            assert ref.status_code == 400, ref.text

    @respx.mock
    async def test_revoke_wrong_client_secret_returns_401(self, app) -> None:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            from openhands.ev2.util.auth_token import create_auth_token

            c.headers["X-API-Key"] = create_auth_token(
                uuid.UUID("12345678-1234-5678-1234-456789abcdef")
            )
            await c.post(
                "/auth/clients",
                json={"client_id": "revoke-2", "client_secret": "right", "redirect_uris": []},
            )
            rev = await c.post(
                "/auth/revoke",
                data={
                    "token": "anything",
                    "client_id": "revoke-2",
                    "client_secret": "wrong",
                },
            )
            assert rev.status_code == 401

    @respx.mock
    async def test_revoke_unknown_token_returns_200(self, app) -> None:
        """A garbage token must still yield 200 (RFC 7009 §2.2 best-effort)."""
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            from openhands.ev2.util.auth_token import create_auth_token

            c.headers["X-API-Key"] = create_auth_token(
                uuid.UUID("12345678-1234-5678-1234-456789abcdef")
            )
            await c.post(
                "/auth/clients",
                json={"client_id": "revoke-3", "client_secret": "s", "redirect_uris": []},
            )
            rev = await c.post(
                "/auth/revoke",
                data={
                    "token": "not-a-real-jwe",
                    "client_id": "revoke-3",
                    "client_secret": "s",
                },
            )
            assert rev.status_code == 200, rev.text

    @respx.mock
    async def test_revoke_access_token_returns_200(self, app) -> None:
        """Revoking an access token returns 200 (best-effort, Option A)."""
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            from openhands.ev2.util.auth_token import create_auth_token

            c.headers["X-API-Key"] = create_auth_token(
                uuid.UUID("12345678-1234-5678-1234-456789abcdef")
            )
            await c.post(
                "/auth/clients",
                json={
                    "client_id": "revoke-4",
                    "client_secret": "revoke-secret",
                    "redirect_uris": ["https://app.example.com/cb"],
                },
            )
            respx.post(f"{_IDP_BASE}/token").mock(
                return_value=httpx.Response(
                    200, json=_idp_token_response("rev4-sub", "rev4@example.com")
                )
            )
            auth = await c.get(
                "/auth/authorize",
                params={
                    "response_type": "code",
                    "client_id": "revoke-4",
                    "redirect_uri": "https://app.example.com/cb",
                },
                follow_redirects=False,
            )
            idp_state = parse_qs(urlparse(auth.headers["location"]).query)["state"][0]
            cb = await c.get(
                "/auth/callback",
                params={"code": "idp-code", "state": idp_state},
                follow_redirects=False,
            )
            our_code = parse_qs(urlparse(cb.headers["location"]).query)["code"][0]
            tok = await c.post(
                "/auth/token",
                json={
                    "grant_type": "authorization_code",
                    "code": our_code,
                    "redirect_uri": "https://app.example.com/cb",
                    "client_id": "revoke-4",
                    "client_secret": "revoke-secret",
                },
            )
            access_token = tok.json()["access_token"]

            rev = await c.post(
                "/auth/revoke",
                data={
                    "token": access_token,
                    "token_type_hint": "access_token",
                    "client_id": "revoke-4",
                    "client_secret": "revoke-secret",
                },
            )
            assert rev.status_code == 200, rev.text

    @respx.mock
    async def test_revoke_idempotent_for_already_revoked(self, app) -> None:
        """Revoking the same refresh token twice yields 200 both times."""
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            from openhands.ev2.util.auth_token import create_auth_token

            c.headers["X-API-Key"] = create_auth_token(
                uuid.UUID("12345678-1234-5678-1234-456789abcdef")
            )
            await c.post(
                "/auth/clients",
                json={
                    "client_id": "revoke-5",
                    "client_secret": "revoke-secret",
                    "redirect_uris": ["https://app.example.com/cb"],
                },
            )
            respx.post(f"{_IDP_BASE}/token").mock(
                return_value=httpx.Response(
                    200, json=_idp_token_response("rev5-sub", "rev5@example.com")
                )
            )
            auth = await c.get(
                "/auth/authorize",
                params={
                    "response_type": "code",
                    "client_id": "revoke-5",
                    "redirect_uri": "https://app.example.com/cb",
                },
                follow_redirects=False,
            )
            idp_state = parse_qs(urlparse(auth.headers["location"]).query)["state"][0]
            cb = await c.get(
                "/auth/callback",
                params={"code": "idp-code", "state": idp_state},
                follow_redirects=False,
            )
            our_code = parse_qs(urlparse(cb.headers["location"]).query)["code"][0]
            tok = await c.post(
                "/auth/token",
                json={
                    "grant_type": "authorization_code",
                    "code": our_code,
                    "redirect_uri": "https://app.example.com/cb",
                    "client_id": "revoke-5",
                    "client_secret": "revoke-secret",
                },
            )
            refresh_token = tok.json()["refresh_token"]

            first = await c.post(
                "/auth/revoke",
                data={
                    "token": refresh_token,
                    "client_id": "revoke-5",
                    "client_secret": "revoke-secret",
                },
            )
            assert first.status_code == 200
            # The refresh token JWE still decrypts; the row is gone, so the
            # second revoke is a best-effort no-op but must still return 200.
            second = await c.post(
                "/auth/revoke",
                data={
                    "token": refresh_token,
                    "client_id": "revoke-5",
                    "client_secret": "revoke-secret",
                },
            )
            assert second.status_code == 200, second.text

    async def test_token_unknown_grant_type(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/auth/token",
            json={"grant_type": "bogus", "client_id": "x", "client_secret": "y"},
        )
        assert resp.status_code == 400

    async def test_refresh_unknown_grant_type(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/auth/refresh",
            json={"grant_type": "bogus", "client_id": "x", "client_secret": "y"},
        )
        assert resp.status_code == 400
