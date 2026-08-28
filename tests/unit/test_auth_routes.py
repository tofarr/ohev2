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
        # (OHEV_BASE_URL=http://test in the test config).
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
