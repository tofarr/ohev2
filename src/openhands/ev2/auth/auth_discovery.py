"""OIDC Discovery (RFC 8414 / OIDC Discovery §3) metadata endpoints.

Serves the provider metadata document at the standard well-known paths so
OIDC clients can auto-configure:

* ``GET /.well-known/openid-configuration`` — the OIDC discovery document.
* ``GET /.well-known/oauth-authorization-server`` — the RFC 8414 OAuth 2.0
  authorization-server metadata (same document, different path).

The document is a pure function of the application config (issuer = base_url)
and the auth feature's advertised endpoints; it carries no state and requires
no authentication. ``jwks_uri`` is intentionally omitted because id_tokens
are signed HS256 with the symmetric key shared with first-party confidential
clients (no public key to publish). See
:meth:`AuthService.build_discovery_document` for the document contents.

The router has no prefix — the well-known paths are served at the application
root, as required by OIDC Discovery (the document URL is
``{issuer}/.well-known/openid-configuration`` with ``issuer == base_url``).
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from openhands.ev2.auth.auth_service import AuthService
from openhands.ev2.db import SessionDep

router = APIRouter(tags=["oidc-discovery"])


@router.get("/.well-known/openid-configuration")
async def openid_configuration(session: SessionDep) -> dict[str, Any]:
    """OIDC discovery document (OIDC Discovery §3)."""
    service = AuthService(session)
    try:
        return service.build_discovery_document()
    finally:
        await service.aclose()


@router.get("/.well-known/oauth-authorization-server")
async def oauth_authorization_server(session: SessionDep) -> dict[str, Any]:
    """RFC 8414 OAuth 2.0 authorization-server metadata (same as OIDC)."""
    service = AuthService(session)
    try:
        return service.build_discovery_document()
    finally:
        await service.aclose()
