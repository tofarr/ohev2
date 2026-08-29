"""Pydantic schemas for the federated OAuth (auth) feature."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from openhands.ev2.auth.auth_models import OAuthClient
from openhands.ev2.util.search_filter import BaseSearchFilter


class AuthorizeRequest(BaseModel):
    """Query parameters for ``GET /auth/authorize`` (RFC 6749 §4.1.1).

    The project acts as an OAuth provider to the client and as a client to the
    IdP, so the same parameters are forwarded to the IdP after the redirect URI
    is validated against the client's allow-list.

    ``response_type`` selects the provider-facing flow:

    * ``code``   — standard OAuth: the callback returns an authorization code
      the client exchanges at ``/auth/token``.
    * ``cookie`` — the callback sets a session cookie and returns no code; the
      browser is authenticated by the cookie alone.
    """

    response_type: Literal["code", "cookie"] = Field(
        description="'code' (standard OAuth, code returned) or 'cookie' "
        "(session cookie set, no code).",
    )
    client_id: str
    redirect_uri: str
    state: str | None = Field(default=None, description="Opaque client state echoed back.")
    scope: str | None = Field(default=None, description="Optional space-delimited scopes.")
    # PKCE (RFC 7636) — optional but recommended.
    code_challenge: str | None = Field(default=None)
    code_challenge_method: str | None = Field(default="plain")


class TokenRequest(BaseModel):
    """Body for ``POST /auth/token`` (RFC 6749 §4.1.3).

    Supports the ``authorization_code`` and ``refresh_token`` grant types.
    Client credentials are validated against the ``oauth_clients`` table.
    """

    grant_type: str = Field(description="'authorization_code' or 'refresh_token'.")
    code: str | None = Field(default=None, description="Authorization code (auth code grant).")
    redirect_uri: str | None = Field(default=None, description="Must match the authorize request.")
    client_id: str
    client_secret: str
    code_verifier: str | None = Field(default=None, description="PKCE code verifier.")
    refresh_token: str | None = Field(default=None, description="Refresh token (refresh grant).")


class DevLoginRequest(BaseModel):
    """Body for ``POST /auth/dev/login``.

    A development-only convenience endpoint that authenticates a user with
    username + password and sets a session cookie directly, bypassing the
    OAuth authorize/callback round trip. Intended for logging in from the
    OpenAPI docs page in a development environment.
    """

    model_config = ConfigDict(
        json_schema_extra={"example": {"username": "dev-user", "password": "dev-pass"}}
    )

    username: str = Field(description="Username of an enabled local user.")
    password: str = Field(description="The user's password.")


class TokenResponse(BaseModel):
    """OAuth2 token response (RFC 6749 §5.1).

    ``access_token`` is a JWE the client sends as ``Authorization: Bearer``;
    ``refresh_token`` is a JWE the client posts to ``/auth/refresh``. Both
    expiries are synced to the federated source: ``expires_at`` /
    ``refresh_token_expires_at`` are absolute drift-adjusted expiries taken
    from the IdP; the ``_in`` siblings are the same as relative seconds for
    client convenience. When the access token expires the client calls
    ``/auth/refresh``; when the refresh token expires the client must
    re-authenticate.
    """

    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int = Field(description="Access-token lifetime in seconds.")
    expires_at: datetime = Field(description="Absolute access-token expiry (drift-adjusted).")
    refresh_token_expires_in: int = Field(description="Refresh-token lifetime in seconds.")
    refresh_token_expires_at: datetime = Field(
        description="Absolute refresh-token expiry (drift-adjusted)."
    )
    id_token: str | None = Field(default=None, description="Optional id_token passthrough.")


class OAuthClientCreate(BaseModel):
    """Payload to register an OAuth client."""

    client_id: str = Field(min_length=1, max_length=128)
    client_secret: str = Field(min_length=1)
    name: str | None = Field(default=None, max_length=255)
    redirect_uris: list[str] = Field(
        default_factory=list,
        description="Permitted redirect URIs; wildcard segments (*) allowed.",
    )
    enabled: bool = True


class OAuthClientUpdate(BaseModel):
    """Partial update of an OAuth client."""

    name: str | None = None
    client_secret: str | None = None
    redirect_uris: list[str] | None = None
    enabled: bool | None = None


class OAuthClientRead(BaseModel):
    """OAuth client representation returned by the API.

    The raw client_secret is never returned.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    client_id: str
    name: str | None
    enabled: bool
    redirect_uris: list[str]
    created_at: datetime
    updated_at: datetime


class OAuthClientSearchFilter(BaseSearchFilter[OAuthClient]):
    """Optional filter clauses for ``GET /auth/clients``."""

    name__contains: str | None = Field(default=None)
    enabled__eq: bool | None = Field(default=None)
    created_at__gte: datetime | None = Field(default=None)
    created_at__lt: datetime | None = Field(default=None)


class OAuthClientSearchResult(BaseModel):
    """Paginated collection of OAuth clients."""

    items: list[OAuthClientRead]
    next_cursor: str | None = Field(default=None)
    limit: int


class UserInfoResponse(BaseModel):
    """OIDC UserInfo response (OIDC Core §5.3).

    Claims are scope-gated: ``sub`` is always present; ``email`` /
    ``email_verified`` require the ``email`` scope; ``name`` /
    ``preferred_username`` require the ``profile`` scope. The response is a
    plain JSON object (not a JWT) per the UserInfo endpoint's default
    ``application/json`` encoding.
    """

    sub: str
    email: str | None = Field(default=None)
    email_verified: bool | None = Field(default=None)
    name: str | None = Field(default=None)
    preferred_username: str | None = Field(default=None)
