"""Pydantic schemas for the secret provider feature (AGENTS.md §12/§13).

Resources:

* ``/secret-providers`` — full CRUD over governed secret-source rows
  (``kind`` + ``data``). ``data`` is a secret-bearing JSONB map: the service
  stores each value as JWE ciphertext and the read surface decrypts-then-masks
  it (plaintext only when the §13 ``expose_secrets`` context flag is set).
* ``/static-secrets`` — full CRUD over the DB-backed store for the
  ``kind="static"`` provider. The ``value`` is a :class:`SecretStr`; responses
  never include it (reveal happens through ``/secret-values``).
* ``/secret-values`` — read-only projection of :class:`SecretValue` served by
  providers, gated by a single USE on the provider.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_serializer, field_validator

from openhands.ev2.secret.secret_models import SecretProvider, StaticSecret
from openhands.ev2.util.search_filter import BaseSearchFilter

# A secret name is env-var compatible: uppercase letters, digits, and
# underscores; first character a letter or underscore.
_NAME_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")


def _validate_name(value: str) -> str:
    value = value.strip()
    if not value or not _NAME_RE.match(value):
        raise ValueError("name must match [A-Z_][A-Z0-9_]* (uppercase, digits, underscores)")
    return value


# --------------------------------------------------------------------------- #
# SecretProvider
# --------------------------------------------------------------------------- #


class SecretProviderCreate(BaseModel):
    """Payload to create a secret provider row.

    ``data`` values are plaintext in transit; the service encrypts each to JWE
    ciphertext before storage. ``data`` keys are treated as literal strings.
    """

    model_config = ConfigDict(populate_by_name=True)

    kind: Literal["static"] = Field(description="Discriminator selecting the provider.")

    data: dict[str, SecretStr] = Field(
        default_factory=dict,
        description="Provider-specific configuration; values encrypted at rest.",
    )

    @field_validator("data", mode="before")
    @classmethod
    def _validate_data(cls, value: Any) -> dict[str, SecretStr] | None:
        if value is None:
            return None
        if not isinstance(value, dict):
            raise ValueError("data must be an object")
        return {str(key): load_secret_str_entry(item) for key, item in value.items()}


def load_secret_str_entry(item: Any) -> SecretStr:
    """Coerce a single ``data`` entry to :class:`SecretStr` for in-memory use."""
    if isinstance(item, SecretStr):
        return item
    return SecretStr(str(item))


class SecretProviderUpdate(BaseModel):
    """Payload to partially update a secret provider row."""

    model_config = ConfigDict(populate_by_name=True)

    data: dict[str, SecretStr] | None = Field(
        default=None,
        description="Provider-specific configuration; values encrypted at rest.",
    )

    @field_validator("data", mode="before")
    @classmethod
    def _validate_data(cls, value: Any) -> dict[str, SecretStr] | None:
        if value is None:
            return None
        if not isinstance(value, dict):
            raise ValueError("data must be an object")
        return {str(key): load_secret_str_entry(item) for key, item in value.items()}


class SecretProviderRead(BaseModel):
    """Secret provider representation returned by the API.

    Stored ``data`` values are JWE ciphertext; the serializer decrypts them and
    re-wraps as :class:`SecretStr`, so values serialize as ``**********`` by
    default. Only a caller that explicitly passes the §13 ``expose_secrets``
    context flag sees plaintext.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    kind: str

    @field_serializer("data")
    def _serialize_data(self, value: dict[str, Any], info: Any) -> dict[str, str]:
        ctx = getattr(info, "context", None)
        expose = bool(ctx.get("expose_secrets")) if isinstance(ctx, dict) else False
        return {str(key): str(item) if expose else "**********" for key, item in value.items()}

    data: dict[str, Any]
    creator_id: uuid.UUID
    created_at: datetime
    updated_at: datetime


class SecretProviderSearchFilter(BaseSearchFilter[SecretProvider]):
    """Optional filter clauses for ``GET /secret-providers``."""

    kind__eq: str | None = Field(default=None)
    creator_id__eq: uuid.UUID | None = Field(default=None)
    created_at__gte: datetime | None = Field(default=None)
    created_at__lt: datetime | None = Field(default=None)
    created_at__gt: datetime | None = Field(default=None)
    created_at__lte: datetime | None = Field(default=None)


class SecretProviderSearchResult(BaseModel):
    """Paginated collection of secret providers."""

    items: list[SecretProviderRead]
    next_cursor: str | None = Field(default=None)
    limit: int


class SecretProviderBatchCreate(BaseModel):
    """Create operation within a secret provider batch write."""

    op: Literal["create"] = "create"
    data: SecretProviderCreate


class SecretProviderBatchUpdate(BaseModel):
    """Update operation within a secret provider batch write."""

    op: Literal["update"] = "update"
    id: uuid.UUID
    data: SecretProviderUpdate


class SecretProviderBatchDelete(BaseModel):
    """Delete operation within a secret provider batch write."""

    op: Literal["delete"] = "delete"
    id: uuid.UUID


SecretProviderBatchOp = Annotated[
    SecretProviderBatchCreate | SecretProviderBatchUpdate | SecretProviderBatchDelete,
    Field(discriminator="op"),
]


class SecretProviderBatchWriteRequest(BaseModel):
    """Request body for ``POST /secret-providers/batch``."""

    operations: list[SecretProviderBatchOp] = Field(min_length=1, max_length=100)


# --------------------------------------------------------------------------- #
# StaticSecret
# --------------------------------------------------------------------------- #


class StaticSecretCreate(BaseModel):
    """Payload to create a static secret."""

    model_config = ConfigDict(populate_by_name=True)

    name: str = Field(min_length=1, max_length=255)
    value: SecretStr = Field(min_length=1, description="The secret payload (plaintext in transit).")
    valid_at: datetime | None = Field(default=None)
    expires_at: datetime | None = Field(default=None)

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str) -> str:
        return _validate_name(value)


class StaticSecretUpdate(BaseModel):
    """Payload to partially update a static secret. All fields optional."""

    model_config = ConfigDict(populate_by_name=True)

    name: str | None = Field(default=None, min_length=1, max_length=255)
    value: SecretStr | None = Field(default=None, min_length=1)
    valid_at: datetime | None = Field(default=None)
    expires_at: datetime | None = Field(default=None)

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _validate_name(value)


class StaticSecretRead(BaseModel):
    """Static secret metadata returned by the CRUD surface.

    The ``value`` is intentionally absent — plaintext is revealed only through
    the ``/secret-values`` projection (single USE gate on the provider).
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    creator_id: uuid.UUID
    valid_at: datetime | None
    expires_at: datetime | None
    created_at: datetime
    updated_at: datetime


class StaticSecretSearchFilter(BaseSearchFilter[StaticSecret]):
    """Optional filter clauses for ``GET /static-secrets``."""

    name__contains: str | None = Field(default=None)
    name__eq: str | None = Field(default=None)
    creator_id__eq: uuid.UUID | None = Field(default=None)
    created_at__gte: datetime | None = Field(default=None)
    created_at__lt: datetime | None = Field(default=None)
    created_at__gt: datetime | None = Field(default=None)
    created_at__lte: datetime | None = Field(default=None)


class StaticSecretSearchResult(BaseModel):
    """Paginated collection of static secrets."""

    items: list[StaticSecretRead]
    next_cursor: str | None = Field(default=None)
    limit: int


class StaticSecretBatchCreate(BaseModel):
    """Create operation within a static secret batch write."""

    op: Literal["create"] = "create"
    data: StaticSecretCreate


class StaticSecretBatchUpdate(BaseModel):
    """Update operation within a static secret batch write."""

    op: Literal["update"] = "update"
    id: uuid.UUID
    data: StaticSecretUpdate


class StaticSecretBatchDelete(BaseModel):
    """Delete operation within a static secret batch write."""

    op: Literal["delete"] = "delete"
    id: uuid.UUID


StaticSecretBatchOp = Annotated[
    StaticSecretBatchCreate | StaticSecretBatchUpdate | StaticSecretBatchDelete,
    Field(discriminator="op"),
]


class StaticSecretBatchWriteRequest(BaseModel):
    """Request body for ``POST /static-secrets/batch``."""

    operations: list[StaticSecretBatchOp] = Field(min_length=1, max_length=100)


# --------------------------------------------------------------------------- #
# SecretValue (read-only reveal projection)
# --------------------------------------------------------------------------- #


class SecretValueRead(BaseModel):
    """A single secret value served by the ``/secret-values`` projection.

    ``id`` is the composite ``{provider_id}/{internal_id}`` string. ``name`` is
    the env-var-compatible handle; ``value`` is the decrypted plaintext — this
    surface exists precisely to reveal it.
    """

    id: str
    provider_id: uuid.UUID
    internal_id: str
    name: str
    value: str
    valid_at: datetime | None = None
    expires_at: datetime | None = None


class SecretValueSearchResult(BaseModel):
    """Paginated collection of secret values from a single provider."""

    items: list[SecretValueRead]
    next_cursor: str | None = Field(default=None)
    limit: int
