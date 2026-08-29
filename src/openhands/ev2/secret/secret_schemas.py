"""Pydantic schemas for the secret feature.

Two resources share the ``/secrets`` and ``/role-secrets`` collections.

Uniform REST surface (AGENTS.md §3):

* ``/secrets`` — full CRUD (GET paginated, POST, GET/PATCH/DELETE /{id}) plus
  batch read/write. The ``value`` is received as a :class:`SecretStr` on create
  /update (so it is never logged carelessly) and returned as a decrypted
  plaintext ``str`` on read, because the read grant *is* the authorization to
  view the value — the per-secret ``role_secrets`` grant controls who may
  retrieve it. There is no separate "reveal" endpoint; GET /secrets/{id}
  returns the value.
* ``/role-secrets`` — full CRUD (the link is mutable: PATCH toggles the
  read/update/delete flags) plus batch read/write.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

from openhands.ev2.secret.secret_models import Secret
from openhands.ev2.util.search_filter import BaseSearchFilter

# A secret code is letters, digits, and underscores only (like a feature-flag
# key). Stable, human-readable, and safe to use as a reference key.
_CODE_RE = re.compile(r"^[A-Za-z0-9_]+$")


# --------------------------------------------------------------------------- #
# Secret
# --------------------------------------------------------------------------- #


class SecretCreate(BaseModel):
    """Payload to create a secret.

    The ``value`` is a :class:`SecretStr` so the plaintext is treated as
    sensitive in transit (it is not repr'd/logged by default). It is encrypted
    at rest by the service before persistence.
    """

    model_config = ConfigDict(populate_by_name=True)

    code: str = Field(min_length=1, max_length=255, description="Letters, digits, underscores.")
    value: SecretStr = Field(min_length=1, description="The secret payload (plaintext in transit).")
    description: str | None = Field(default=None, max_length=4096)

    @field_validator("code")
    @classmethod
    def _validate_code(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("code must be a non-empty string")
        if not _CODE_RE.match(v):
            raise ValueError("code may only contain letters, digits, and underscores")
        return v


class SecretUpdate(BaseModel):
    """Partial update of a secret. All fields optional."""

    model_config = ConfigDict(populate_by_name=True)

    code: str | None = Field(default=None, min_length=1, max_length=255)
    value: SecretStr | None = Field(default=None, min_length=1)
    description: str | None = Field(default=None, max_length=4096)

    @field_validator("code")
    @classmethod
    def _validate_code(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip()
        if not v:
            raise ValueError("code must be a non-empty string")
        if not _CODE_RE.match(v):
            raise ValueError("code may only contain letters, digits, and underscores")
        return v


class SecretRead(BaseModel):
    """Secret representation returned by the API.

    The decrypted ``value`` is returned as a plaintext ``str``. The read grant
    (``role_secrets.read_enabled`` for one of the principal's roles, or a
    ``Permitted`` secret policy) *is* the authorization to view the value, so
    there is no separate reveal endpoint.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    code: str
    value: str
    description: str | None
    user_id: uuid.UUID
    created_at: datetime
    updated_at: datetime


class SecretSearchFilter(BaseSearchFilter[Secret]):
    """Optional filter clauses for ``GET /secrets``."""

    code__contains: str | None = Field(default=None, description="Case-insensitive code substring.")
    code__eq: str | None = Field(default=None, description="Exact code match.")
    user_id__eq: uuid.UUID | None = Field(default=None, description="Exact creator user id match.")
    created_at__gte: datetime | None = Field(
        default=None, description="ISO 8601; created at or after."
    )
    created_at__lt: datetime | None = Field(default=None, description="ISO 8601; created before.")
    created_at__gt: datetime | None = Field(
        default=None, description="ISO 8601; created strictly after."
    )
    created_at__lte: datetime | None = Field(
        default=None, description="ISO 8601; created at or before."
    )


class SecretSearchResult(BaseModel):
    """Paginated collection of secrets."""

    items: list[SecretRead]
    next_cursor: str | None = Field(
        default=None,
        description="Opaque cursor for the next page; null when no more results.",
    )
    limit: int


# --------------------------------------------------------------------------- #
# Secret batch write
# --------------------------------------------------------------------------- #


class SecretBatchCreate(BaseModel):
    """Create operation within a secret batch write."""

    op: Literal["create"] = "create"
    data: SecretCreate


class SecretBatchUpdate(BaseModel):
    """Update operation within a secret batch write."""

    op: Literal["update"] = "update"
    id: uuid.UUID
    data: SecretUpdate


class SecretBatchDelete(BaseModel):
    """Delete operation within a secret batch write."""

    op: Literal["delete"] = "delete"
    id: uuid.UUID


SecretBatchOp = Annotated[
    SecretBatchCreate | SecretBatchUpdate | SecretBatchDelete,
    Field(discriminator="op"),
]


class SecretBatchWriteRequest(BaseModel):
    """Request body for ``POST /secrets/batch``."""

    operations: list[SecretBatchOp] = Field(
        min_length=1,
        max_length=100,
        description="Operations to apply atomically; create/update/delete mixed.",
    )
