"""Pydantic schemas for the typed secret feature.

Resources:

* ``/secrets`` — full CRUD (GET paginated, POST, GET/PATCH/DELETE /{id}) plus
  batch read/write. Responses return metadata only — the ``value`` is never
  exposed here. The ``value`` is received as a :class:`SecretStr` on create
  /update (so it is never logged carelessly) and stored encrypted in a
  type-specific detail table by the service.
* ``/secret-values`` — read-only projection that reveals decrypted plaintext.
  It aggregates across secret types and is governed by the separate
  ``secret_value_permission`` column; a secret is revealed only when the
  principal has both read access to the secret and the value-reveal permission
  (defense in depth, AGENTS.md §12).
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

from openhands.ev2.secret.secret_models import Secret, SecretType
from openhands.ev2.util.search_filter import BaseSearchFilter

# A secret code is letters, digits, and underscores only (like a feature-flag
# key). Stable, human-readable, and safe to use as a reference key.
_CODE_RE = re.compile(r"^[A-Za-z0-9_]+$")


# --------------------------------------------------------------------------- #
# Secret
# --------------------------------------------------------------------------- #


class SecretCreate(BaseModel):
    """Payload to create a secret.

    ``type`` defaults to ``static``. ``value`` is a :class:`SecretStr` so the
    plaintext is treated as sensitive in transit (it is not repr'd/logged by
    default) and is required when ``type == static``; it must be omitted when
    ``type == oauth`` (no oauth detail table exists yet). The value is
    encrypted at rest by the service before persistence.
    """

    model_config = ConfigDict(populate_by_name=True)

    code: str = Field(min_length=1, max_length=255, description="Letters, digits, underscores.")
    type: SecretType = Field(default=SecretType.STATIC, description="Secret type discriminator.")
    value: SecretStr | None = Field(
        default=None, min_length=1, description="The secret payload (plaintext in transit)."
    )
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

    @model_validator(mode="after")
    def _validate_value_for_type(self) -> SecretCreate:
        if self.type == SecretType.STATIC and self.value is None:
            raise ValueError("value is required when type is static")
        if self.type == SecretType.OAUTH and self.value is not None:
            raise ValueError("value is not allowed for type oauth")
        return self


class SecretUpdate(BaseModel):
    """Partial update of a secret. All fields optional.

    ``value`` is allowed only when the secret's type is ``static``; the service
    enforces this and raises :class:`SecretValueTypeError` for oauth. ``type``
    itself is immutable after create and therefore absent here.
    """

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
    """Secret metadata returned by the ``/secrets`` surface.

    The ``value`` is intentionally absent — decrypted plaintext is revealed
    only through the ``/secret-values`` projection (AGENTS.md §12).
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    code: str
    type: SecretType
    description: str | None
    creator_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime


class SecretSearchFilter(BaseSearchFilter[Secret]):
    """Optional filter clauses for ``GET /secrets``."""

    code__contains: str | None = Field(default=None, description="Case-insensitive code substring.")
    code__eq: str | None = Field(default=None, description="Exact code match.")
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
    """Paginated collection of secret metadata."""

    items: list[SecretRead]
    next_cursor: str | None = Field(
        default=None,
        description="Opaque cursor for the next page; null when no more results.",
    )
    limit: int


# --------------------------------------------------------------------------- #
# Secret value reveal (/secret-values)
# --------------------------------------------------------------------------- #


class SecretValueRead(BaseModel):
    """A decrypted secret value returned by the ``/secret-values`` projection.

    This is the only API shape that carries plaintext. A principal receives it
    only when they have both read access to the secret (``secret_permission``)
    and the value-reveal permission (``secret_value_permission``).
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    code: str
    type: SecretType
    value: str


class SecretValueSearchResult(BaseModel):
    """Paginated collection of revealed secret values."""

    items: list[SecretValueRead]
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
