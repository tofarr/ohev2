"""Pydantic schemas for the governed ``/oauth/sessions`` resource.

Uniform REST surface (AGENTS.md §3): standard CRUD + batch read/write. Create
is unusual — sessions are produced by the login/consent flow
(``POST /oauth/providers/{id}/authorize`` → ``GET /oauth/providers/{id}/callback``)
rather than a direct ``POST /oauth/sessions``. Read/update/delete are standard.

The encrypted ``access_token`` and ``refresh_token`` are never exposed through
the CRUD surface (only through ``/secret-values``, sub-issue #145).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from openhands.ev2.oauth.oauth_session_models import OAuthSession
from openhands.ev2.util.search_filter import BaseSearchFilter


class OAuthSessionRead(BaseModel):
    """OAuth session representation returned by the API.

    The encrypted ``access_token`` and ``refresh_token`` are intentionally
    absent — plaintext is revealed only through the ``/secret-values``
    projection (single USE gate, §12.1).
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    oauth_provider_id: uuid.UUID
    creator_id: uuid.UUID
    access_token_expires_at: datetime
    refresh_token_expires_at: datetime | None
    tolerate_invalid: bool
    enabled: bool
    created_at: datetime
    updated_at: datetime


class OAuthSessionUpdate(BaseModel):
    """Payload to partially update an OAuth session. All fields optional."""

    model_config = ConfigDict(populate_by_name=True)

    tolerate_invalid: bool | None = Field(default=None)
    enabled: bool | None = Field(default=None)


class OAuthSessionSearchFilter(BaseSearchFilter[OAuthSession]):
    """Optional filter clauses for ``GET /oauth/sessions``."""

    oauth_provider_id__eq: uuid.UUID | None = Field(default=None)
    creator_id__eq: uuid.UUID | None = Field(default=None)
    enabled__eq: bool | None = Field(default=None)
    created_at__gte: datetime | None = Field(default=None)
    created_at__lt: datetime | None = Field(default=None)
    created_at__gt: datetime | None = Field(default=None)
    created_at__lte: datetime | None = Field(default=None)


class OAuthSessionSearchResult(BaseModel):
    """Paginated collection of OAuth sessions."""

    items: list[OAuthSessionRead]
    next_cursor: str | None = Field(default=None)
    limit: int


class OAuthSessionBatchUpdate(BaseModel):
    """Update operation within an OAuth session batch write."""

    op: Literal["update"] = "update"
    id: uuid.UUID
    data: OAuthSessionUpdate


class OAuthSessionBatchDelete(BaseModel):
    """Delete operation within an OAuth session batch write."""

    op: Literal["delete"] = "delete"
    id: uuid.UUID


OAuthSessionBatchOp = Annotated[
    OAuthSessionBatchUpdate | OAuthSessionBatchDelete,
    Field(discriminator="op"),
]


class OAuthSessionBatchWriteRequest(BaseModel):
    """Request body for ``POST /oauth/sessions/batch``."""

    operations: list[OAuthSessionBatchOp] = Field(min_length=1, max_length=100)


class AuthorizeResponse(BaseModel):
    """Response from ``POST /oauth/providers/{id}/authorize``."""

    authorize_url: str
    state: str


class AuthorizeRequest(BaseModel):
    """Request body for ``POST /oauth/providers/{id}/authorize``.

    ``redirect_uri`` is the URL the browser is redirected to after the callback
    completes. ``state`` is an opaque client value carried through the flow.
    """

    redirect_uri: str = Field(min_length=1, max_length=2048)
    state: str | None = Field(default=None, max_length=2048)
    scope: str | None = Field(default=None)
    code_challenge: str | None = Field(default=None, max_length=512)
    code_challenge_method: str | None = Field(default=None, max_length=16)
