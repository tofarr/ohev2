"""Pydantic schemas for the auth feature."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from openhands.ev2.auth.auth_models import ApiKey, TokenType
from openhands.ev2.util.search_filter import BaseSearchFilter


class LoginRequest(BaseModel):
    """Credentials submitted to the password/cookie login endpoint."""

    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1)


class LoginResponse(BaseModel):
    """Successful cookie-login response.

    The session cookie is set alongside this body; ``token_type`` advertises
    the cookie flow so clients know to rely on the cookie.
    """

    user_id: uuid.UUID
    username: str
    token_type: TokenType = TokenType.COOKIE


class OAuthTokenRequest(BaseModel):
    """OAuth2 password-grant token request (RFC 6749 §4.3).

    ``grant_type`` is required to be ``password`` for this flow; later
    ``refresh_token`` grant reuses a subset of this schema via
    :class:`RefreshRequest`.
    """

    grant_type: str = Field(description="Must be 'password'.")
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1)
    # Optional scope kept for forward-compat; not enforced yet.
    scope: str | None = Field(default=None, description="Space-delimited scope list.")


class RefreshRequest(BaseModel):
    """OAuth2 refresh-token-grant request (RFC 6749 §6)."""

    grant_type: str = Field(description="Must be 'refresh_token'.")
    refresh_token: str = Field(min_length=1)


class OAuthTokenResponse(BaseModel):
    """OAuth2 token response (RFC 6749 §5.1).

    ``access_token`` is a JWE the client sends as ``Authorization: Bearer``;
    ``refresh_token`` is a JWE the client posts to ``/auth/refresh``.
    """

    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int = Field(description="Access-token lifetime in seconds.")


class ApiKeyCreate(BaseModel):
    """Payload to mint an API key for the current user."""

    model_config = ConfigDict(populate_by_name=True)

    name: str | None = Field(default=None, description="Optional human label.")
    expires_at: datetime | None = Field(
        default=None,
        description="Optional absolute expiry; null = no expiry.",
    )


class ApiKeyRead(BaseModel):
    """API key representation returned by the API.

    The raw token string is returned only once, at creation time, in
    :class:`ApiKeyCreateResponse`; :class:`ApiKeyRead` omits it.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    jti: uuid.UUID
    user_id: uuid.UUID
    name: str | None
    enabled: bool
    expires_at: datetime | None
    created_at: datetime
    updated_at: datetime


class ApiKeyCreateResponse(BaseModel):
    """API key creation response: includes the raw token once.

    The ``token`` is the JWE the client sends as ``X-API-Key``; it is never
    retrievable again after creation.
    """

    api_key: ApiKeyRead
    token: str = Field(description="The raw X-API-Key value; store securely.")


class ApiKeyUpdate(BaseModel):
    """Partial update of an API key (enable/disable, rename, re-expire)."""

    model_config = ConfigDict(populate_by_name=True)

    name: str | None = None
    enabled: bool | None = None
    expires_at: datetime | None = None


class ApiKeySearchFilter(BaseSearchFilter[ApiKey]):
    """Optional filter clauses for `GET /auth/api-keys`."""

    name__contains: str | None = Field(default=None, description="Case-insensitive name substring.")
    enabled__eq: bool | None = Field(default=None, description="Exact enabled match.")
    created_at__gte: datetime | None = Field(default=None)
    created_at__lt: datetime | None = Field(default=None)


class ApiKeySearchResult(BaseModel):
    """Paginated collection of API keys."""

    items: list[ApiKeyRead]
    next_cursor: str | None = Field(
        default=None,
        description="Opaque cursor for the next page; null when no more results.",
    )
    limit: int
