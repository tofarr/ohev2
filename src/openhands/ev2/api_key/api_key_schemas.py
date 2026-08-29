"""Pydantic schemas for the api_key feature.

Uniform REST surface (AGENTS.md §3): the collection is ``/api-keys`` with
cursor pagination; create is ``POST``, update is ``PATCH``, retrieve is
``GET``, and remove is ``DELETE``. The backing ORM model
(:class:`ApiKey`) and the ``api_key_permission`` role column already exist in
the auth package; this feature only adds the CRUD surface.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from openhands.ev2.auth.auth_models import ApiKey
from openhands.ev2.util.search_filter import BaseSearchFilter


class ApiKeyCreate(BaseModel):
    """Payload to create an API key.

    ``user_id`` is required: an API key always belongs to a user (the subject
    of the minted JWE). ``expires_at`` is optional; ``None`` means the key
    never expires on its own.
    """

    model_config = ConfigDict(populate_by_name=True)

    user_id: uuid.UUID
    name: str | None = Field(default=None, max_length=255)
    enabled: bool = True
    expires_at: datetime | None = Field(
        default=None,
        description="ISO 8601; null means the key never expires on its own.",
    )

    @field_validator("name")
    @classmethod
    def _strip_name(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip()
        if not v:
            raise ValueError("name must be a non-empty string")
        return v


class ApiKeyUpdate(BaseModel):
    """Payload to partially update an API key. All fields optional.

    ``jti`` and ``user_id`` are immutable: the token's identity and subject
    cannot change after minting.
    """

    model_config = ConfigDict(populate_by_name=True)

    name: str | None = Field(default=None, max_length=255)
    enabled: bool | None = None
    expires_at: datetime | None = Field(
        default=None,
        description="ISO 8601; null means the key never expires on its own.",
    )

    @field_validator("name")
    @classmethod
    def _strip_name(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip()
        if not v:
            raise ValueError("name must be a non-empty string")
        return v


class ApiKeyRead(BaseModel):
    """API key representation returned by the API.

    The JWE token secret is never returned here; it is surfaced only once, on
    the single-item create response (:class:`ApiKeyCreated`).
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


class ApiKeyCreated(ApiKeyRead):
    """Single-item create response carrying the one-time JWE secret.

    The ``token`` is the only time the raw credential is surfaced to a client;
    it is not stored or recoverable. Batch creates do not return tokens
    (AGENTS.md §3 — batch write returns ``Read`` for create/update).
    """

    token: str = Field(description="The JWE API-key token; shown only once.")


class ApiKeySearchFilter(BaseSearchFilter[ApiKey]):
    """Optional filter clauses for ``GET /api-keys``.

    Field names follow the ``<attr>__<op>`` convention so the base class derives
    both the in-memory ``matches`` predicate and the SQL ``filter_sql`` clauses
    automatically. Every field is optional; an unset filter matches everything.
    """

    name__contains: str | None = Field(default=None, description="Case-insensitive name substring.")
    name__eq: str | None = Field(default=None, description="Exact name match.")
    user_id__eq: uuid.UUID | None = Field(default=None, description="Exact user id match.")
    enabled__eq: bool | None = Field(default=None, description="Exact enabled match.")
    expires_at__gte: datetime | None = Field(
        default=None, description="ISO 8601; keys expiring at or after."
    )
    expires_at__lt: datetime | None = Field(
        default=None, description="ISO 8601; keys expiring before."
    )
    expires_at__gt: datetime | None = Field(
        default=None, description="ISO 8601; keys expiring strictly after."
    )
    expires_at__lte: datetime | None = Field(
        default=None, description="ISO 8601; keys expiring at or before."
    )
    created_at__gte: datetime | None = Field(
        default=None, description="ISO 8601; keys created at or after."
    )
    created_at__lt: datetime | None = Field(
        default=None, description="ISO 8601; keys created before."
    )
    created_at__gt: datetime | None = Field(
        default=None, description="ISO 8601; keys created strictly after."
    )
    created_at__lte: datetime | None = Field(
        default=None, description="ISO 8601; keys created at or before."
    )


class ApiKeySearchResult(BaseModel):
    """Paginated collection of API keys."""

    items: list[ApiKeyRead]
    next_cursor: str | None = Field(
        default=None,
        description="Opaque cursor for the next page; null when no more results.",
    )
    limit: int


# Batch write: POST /api-keys/batch applies create/update/delete atomically
# (AGENTS.md §3). Operations reuse ApiKeyCreate/ApiKeyUpdate; updates and
# deletes target a specific id. Batch creates return ApiKeyRead (no token).


class ApiKeyBatchCreate(BaseModel):
    """Create operation within an API-key batch write.

    The minted JWE token is not returned for batch creates (AGENTS.md §3 —
    batch write returns ``Read`` for create/update). Retrieve the row id and
    mint a new key via the single-item endpoint if the secret is needed.
    """

    op: Literal["create"] = "create"
    data: ApiKeyCreate


class ApiKeyBatchUpdate(BaseModel):
    """Update operation within an API-key batch write."""

    op: Literal["update"] = "update"
    id: uuid.UUID
    data: ApiKeyUpdate


class ApiKeyBatchDelete(BaseModel):
    """Delete operation within an API-key batch write."""

    op: Literal["delete"] = "delete"
    id: uuid.UUID


ApiKeyBatchOp = Annotated[
    ApiKeyBatchCreate | ApiKeyBatchUpdate | ApiKeyBatchDelete,
    Field(discriminator="op"),
]


class ApiKeyBatchWriteRequest(BaseModel):
    """Request body for ``POST /api-keys/batch``."""

    operations: list[ApiKeyBatchOp] = Field(
        min_length=1,
        max_length=100,
        description="Operations to apply atomically; create/update/delete mixed.",
    )


__all__ = [
    "ApiKey",
    "ApiKeyBatchWriteRequest",
    "ApiKeyCreate",
    "ApiKeyCreated",
    "ApiKeyRead",
    "ApiKeySearchFilter",
    "ApiKeySearchResult",
    "ApiKeyUpdate",
]
