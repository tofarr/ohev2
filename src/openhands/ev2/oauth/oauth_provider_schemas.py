"""Pydantic schemas for the governed ``/oauth/providers`` resource.

Uniform REST surface (AGENTS.md §3): full CRUD with batch read/write and
cursor pagination. ``client_secret`` follows the §13 serialization standard:
encrypted on create/update (JWE ciphertext at rest), masked ``**********`` on
read, plaintext only with ``expose_secrets``.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

from openhands.ev2.oauth.oauth_provider_models import OAuthProvider
from openhands.ev2.util.search_filter import BaseSearchFilter


class OAuthProviderCreate(BaseModel):
    """Payload to create an OAuth provider row.

    ``client_secret`` is plaintext in transit; the service encrypts it to JWE
    ciphertext before storage.
    """

    model_config = ConfigDict(populate_by_name=True)

    name: str = Field(min_length=1, max_length=255)
    url: str = Field(min_length=1, max_length=2048)
    client_id: str = Field(min_length=1, max_length=255)
    client_secret: SecretStr = Field(
        min_length=1, description="Client secret (plaintext in transit)."
    )
    scopes: list[str] = Field(default_factory=list)
    expire_drift_tolerance: int = Field(default=60, ge=0)
    authorize_path: str = Field(default="/authorize", max_length=255)
    token_path: str = Field(default="/token", max_length=255)
    refresh_path: str = Field(default="/token", max_length=255)
    revocation_path: str | None = Field(default=None, max_length=255)
    access_token_expires_in: int = Field(default=900, ge=1)
    refresh_token_expires_in: int = Field(default=2_592_000, ge=1)
    enabled: bool = Field(default=True)

    @field_validator("name")
    @classmethod
    def _strip_name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("name must be a non-empty string")
        return value


class OAuthProviderUpdate(BaseModel):
    """Payload to partially update an OAuth provider row. All fields optional."""

    model_config = ConfigDict(populate_by_name=True)

    name: str | None = Field(default=None, min_length=1, max_length=255)
    url: str | None = Field(default=None, min_length=1, max_length=2048)
    client_id: str | None = Field(default=None, min_length=1, max_length=255)
    client_secret: SecretStr | None = Field(default=None, min_length=1)
    scopes: list[str] | None = Field(default=None)
    expire_drift_tolerance: int | None = Field(default=None, ge=0)
    authorize_path: str | None = Field(default=None, max_length=255)
    token_path: str | None = Field(default=None, max_length=255)
    refresh_path: str | None = Field(default=None, max_length=255)
    revocation_path: str | None = Field(default=None, max_length=255)
    access_token_expires_in: int | None = Field(default=None, ge=1)
    refresh_token_expires_in: int | None = Field(default=None, ge=1)
    enabled: bool | None = Field(default=None)

    @field_validator("name")
    @classmethod
    def _strip_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value:
            raise ValueError("name must be a non-empty string")
        return value


class OAuthProviderRead(BaseModel):
    """OAuth provider representation returned by the API.

    ``client_secret`` is masked ``**********`` by default; only a caller that
    passes the §13 ``expose_secrets`` context flag sees plaintext.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    creator_id: uuid.UUID
    url: str
    client_id: str
    client_secret: str
    scopes: list[str]
    expire_drift_tolerance: int
    authorize_path: str
    token_path: str
    refresh_path: str
    revocation_path: str | None
    access_token_expires_in: int
    refresh_token_expires_in: int
    enabled: bool
    created_at: datetime
    updated_at: datetime


class OAuthProviderSearchFilter(BaseSearchFilter[OAuthProvider]):
    """Optional filter clauses for ``GET /oauth/providers``."""

    name__contains: str | None = Field(default=None)
    name__eq: str | None = Field(default=None)
    enabled__eq: bool | None = Field(default=None)
    creator_id__eq: uuid.UUID | None = Field(default=None)
    created_at__gte: datetime | None = Field(default=None)
    created_at__lt: datetime | None = Field(default=None)
    created_at__gt: datetime | None = Field(default=None)
    created_at__lte: datetime | None = Field(default=None)


class OAuthProviderSearchResult(BaseModel):
    """Paginated collection of OAuth providers."""

    items: list[OAuthProviderRead]
    next_cursor: str | None = Field(default=None)
    limit: int


class OAuthProviderBatchCreate(BaseModel):
    """Create operation within an OAuth provider batch write."""

    op: Literal["create"] = "create"
    data: OAuthProviderCreate


class OAuthProviderBatchUpdate(BaseModel):
    """Update operation within an OAuth provider batch write."""

    op: Literal["update"] = "update"
    id: uuid.UUID
    data: OAuthProviderUpdate


class OAuthProviderBatchDelete(BaseModel):
    """Delete operation within an OAuth provider batch write."""

    op: Literal["delete"] = "delete"
    id: uuid.UUID


OAuthProviderBatchOp = Annotated[
    OAuthProviderBatchCreate | OAuthProviderBatchUpdate | OAuthProviderBatchDelete,
    Field(discriminator="op"),
]


class OAuthProviderBatchWriteRequest(BaseModel):
    """Request body for ``POST /oauth/providers/batch``."""

    operations: list[OAuthProviderBatchOp] = Field(min_length=1, max_length=100)
