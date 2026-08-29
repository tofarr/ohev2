"""Guards the OpenAPI auth surface (AGENTS.md §9).

The auth headers (X-API-Key, Authorization) must be surfaced as security
schemes, not as per-operation header parameters, and the protected endpoints
must carry a security requirement. These regress if the auth dependency
declares the headers with `Header()` instead of `Security(...)`.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI

_AUTH_HEADERS = {"x-api-key", "authorization"}


@pytest.fixture
def openapi_spec(app: FastAPI) -> dict[str, object]:
    return app.openapi()


_PUBLIC_PATHS = {
    "/health",
    # auth OAuth entry points — public by design (they mint or revoke
    # credentials, authenticating via client credentials in the body or,
    # for logout, via the session cookie itself).
    "/auth/authorize",
    "/auth/callback",
    "/auth/token",
    "/auth/refresh",
    # OIDC Discovery (RFC 8414 / OIDC Discovery §3) — public metadata document,
    # intentionally unauthenticated so clients can auto-configure.
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/auth/revoke",
    "/auth/logout",
}


def _protected_ops(spec: dict[str, object]) -> list[tuple[str, str, dict[str, object]]]:
    out: list[tuple[str, str, dict[str, object]]] = []
    for path, methods in spec["paths"].items():  # type: ignore[index]
        for method, op in methods.items():  # type: ignore[index]
            if not isinstance(op, dict):
                continue
            if method.upper() not in {"GET", "POST", "PATCH", "DELETE", "PUT"}:
                continue
            # Skip intentionally public entry points (health + token minting).
            if path in _PUBLIC_PATHS:
                continue
            out.append((path, method, op))
    return out


def test_security_schemes_are_defined(openapi_spec: dict[str, object]) -> None:
    schemes = openapi_spec["components"]["securitySchemes"]  # type: ignore[index]
    assert "ApiKey" in schemes
    assert "BearerAuth" in schemes
    assert schemes["ApiKey"]["in"] == "header"  # type: ignore[index]
    assert schemes["ApiKey"]["name"] == "X-API-Key"  # type: ignore[index]
    assert schemes["BearerAuth"]["scheme"] == "bearer"  # type: ignore[index]


def test_auth_headers_are_not_operation_parameters(
    openapi_spec: dict[str, object],
) -> None:
    for _path, _method, op in _protected_ops(openapi_spec):
        header_params = {
            p["name"].lower()
            for p in op.get("parameters", [])  # type: ignore[union-attr]
            if p.get("in") == "header"  # type: ignore[union-attr]
        }
        leaked = header_params & _AUTH_HEADERS
        assert not leaked, f"auth headers leaked as params: {leaked}"


def test_protected_endpoints_carry_security(
    openapi_spec: dict[str, object],
) -> None:
    for path, _method, op in _protected_ops(openapi_spec):
        security = op.get("security")  # type: ignore[union-attr]
        assert security, f"{path} missing security requirement"
        scheme_names = {name for req in security for name in req}  # type: ignore[index]
        assert "ApiKey" in scheme_names
        assert "BearerAuth" in scheme_names


def test_health_and_auth_token_endpoints_are_public(openapi_spec: dict[str, object]) -> None:
    paths = openapi_spec["paths"]  # type: ignore[index]
    assert not paths["/health"]["get"].get("security")  # type: ignore[index]
    assert not paths["/auth/authorize"]["get"].get("security")  # type: ignore[index]
    assert not paths["/auth/callback"]["get"].get("security")  # type: ignore[index]
    assert not paths["/auth/token"]["post"].get("security")  # type: ignore[index]
    assert not paths["/auth/refresh"]["post"].get("security")  # type: ignore[index]
    # OIDC Discovery endpoints are public (unauthenticated metadata).
    assert not paths["/.well-known/openid-configuration"]["get"].get("security")  # type: ignore[index]
    assert not paths["/.well-known/oauth-authorization-server"]["get"].get("security")  # type: ignore[index]
    assert not paths["/auth/revoke"]["post"].get("security")  # type: ignore[index]
    assert not paths["/auth/logout"]["post"].get("security")  # type: ignore[index]
