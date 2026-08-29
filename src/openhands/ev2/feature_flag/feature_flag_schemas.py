"""Pydantic schemas for the feature_flag feature.

Uniform REST surface (AGENTS.md §3). Two collections:

* ``/feature-flags`` — full CRUD (create/GET/PATCH/DELETE) + batch read/write +
  count. The feature-flag ``id`` is a caller-supplied string of uppercase
  letters, digits, and underscores; it is the primary key.
* ``/feature-flag-roles`` — immutable link rows (create/GET/DELETE + batch
  read/write + count, no ``PATCH``). To change an override, delete and
  re-create, mirroring ``/user-roles``.

The ``feature_flag_permission`` and ``feature_flag_role_permission`` columns on
:class:`Role` govern these resources (AGENTS.md §11).
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from openhands.ev2.feature_flag.feature_flag_models import FeatureFlag, FeatureFlagRole
from openhands.ev2.util.search_filter import BaseSearchFilter

# Feature-flag ids are restricted to uppercase letters, digits, and
# underscores so they are readable in configuration and code and safe as URL
# path segments without escaping.
_FEATURE_FLAG_ID_RE = re.compile(r"^[A-Z0-9_]+$")
_FEATURE_FLAG_ID_MAX = 128


def _validate_feature_flag_id(v: str) -> str:
    v = v.strip()
    if not v:
        raise ValueError("id must be a non-empty string")
    if len(v) > _FEATURE_FLAG_ID_MAX:
        raise ValueError(f"id must be at most {_FEATURE_FLAG_ID_MAX} characters")
    if not _FEATURE_FLAG_ID_RE.match(v):
        raise ValueError("id must contain only uppercase letters, digits, and underscores")
    return v


# ---------------------------------------------------------------------- #
# Feature flag
# ---------------------------------------------------------------------- #


class FeatureFlagCreate(BaseModel):
    """Payload to create a feature flag.

    ``id`` is the caller-supplied primary key (uppercase letters, digits,
    underscores). ``enabled`` defaults to ``False``; ``description`` is
    optional.
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(
        description="Stable, human-readable id (A-Z, 0-9, _). The primary key.",
    )
    enabled: bool = False
    description: str | None = Field(default=None, max_length=2048)

    @field_validator("id")
    @classmethod
    def _validate_id(cls, v: str) -> str:
        return _validate_feature_flag_id(v)

    @field_validator("description")
    @classmethod
    def _strip_description(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip()
        return v or None


class FeatureFlagUpdate(BaseModel):
    """Payload to partially update a feature flag. All fields optional.

    ``id`` is immutable (it is the primary key).
    """

    model_config = ConfigDict(populate_by_name=True)

    enabled: bool | None = None
    description: str | None = Field(default=None, max_length=2048)

    @field_validator("description")
    @classmethod
    def _strip_description(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip()
        return v or None


class FeatureFlagRead(BaseModel):
    """Feature flag representation returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    enabled: bool
    description: str | None
    created_at: datetime
    updated_at: datetime


class FeatureFlagSearchFilter(BaseSearchFilter[FeatureFlag]):
    """Optional filter clauses for ``GET /feature-flags``.

    Field names follow the ``<attr>__<op>`` convention so the base class derives
    both the in-memory ``matches`` predicate and the SQL ``filter_sql`` clauses
    automatically. Every field is optional; an unset filter matches everything.
    """

    id__contains: str | None = Field(default=None, description="Case-insensitive id substring.")
    id__eq: str | None = Field(default=None, description="Exact id match.")
    enabled__eq: bool | None = Field(default=None, description="Exact enabled match.")
    description__contains: str | None = Field(
        default=None, description="Case-insensitive description substring."
    )
    created_at__gte: datetime | None = Field(
        default=None, description="ISO 8601; flags created at or after."
    )
    created_at__lt: datetime | None = Field(
        default=None, description="ISO 8601; flags created before."
    )
    created_at__gt: datetime | None = Field(
        default=None, description="ISO 8601; flags created strictly after."
    )
    created_at__lte: datetime | None = Field(
        default=None, description="ISO 8601; flags created at or before."
    )


class FeatureFlagSearchResult(BaseModel):
    """Paginated collection of feature flags."""

    items: list[FeatureFlagRead]
    next_cursor: str | None = Field(
        default=None,
        description="Opaque cursor for the next page; null when no more results.",
    )
    limit: int


class EnabledFeatureFlags(BaseModel):
    """The set of feature-flag ids enabled for the current user.

    A flag is included when it is globally enabled OR when the user holds a role
    with an override row for that flag (the override forces the flag on for that
    role regardless of the global ``enabled`` value).
    """

    flags: list[str] = Field(description="Ids of feature flags enabled for the current user.")


# Batch write: POST /feature-flags/batch applies create/update/delete atomically
# (AGENTS.md §3). Operations reuse FeatureFlagCreate/FeatureFlagUpdate; updates
# and deletes target a specific id.


class FeatureFlagBatchCreate(BaseModel):
    """Create operation within a feature-flag batch write."""

    op: Literal["create"] = "create"
    data: FeatureFlagCreate


class FeatureFlagBatchUpdate(BaseModel):
    """Update operation within a feature-flag batch write."""

    op: Literal["update"] = "update"
    id: str
    data: FeatureFlagUpdate


class FeatureFlagBatchDelete(BaseModel):
    """Delete operation within a feature-flag batch write."""

    op: Literal["delete"] = "delete"
    id: str


FeatureFlagBatchOp = Annotated[
    FeatureFlagBatchCreate | FeatureFlagBatchUpdate | FeatureFlagBatchDelete,
    Field(discriminator="op"),
]


class FeatureFlagBatchWriteRequest(BaseModel):
    """Request body for ``POST /feature-flags/batch``."""

    operations: list[FeatureFlagBatchOp] = Field(
        min_length=1,
        max_length=100,
        description="Operations to apply atomically; create/update/delete mixed.",
    )


# ---------------------------------------------------------------------- #
# Feature flag role override (link table)
# ---------------------------------------------------------------------- #


class FeatureFlagRoleCreate(BaseModel):
    """Payload to attach a role override to a feature flag.

    The presence of the resulting row makes the flag enabled for any user
    holding ``role_id``, regardless of the flag's global ``enabled`` value.
    """

    model_config = ConfigDict(populate_by_name=True)

    feature_flag_id: str = Field(
        description="The feature flag id this override attaches to.",
    )
    role_id: uuid.UUID

    @field_validator("feature_flag_id")
    @classmethod
    def _validate_feature_flag_id(cls, v: str) -> str:
        return _validate_feature_flag_id(v)


class FeatureFlagRoleRead(BaseModel):
    """Feature-flag role override representation returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    feature_flag_id: str
    role_id: uuid.UUID
    created_at: datetime


class FeatureFlagRoleSearchFilter(BaseSearchFilter[FeatureFlagRole]):
    """Optional filter clauses for ``GET /feature-flag-roles``."""

    feature_flag_id__eq: str | None = Field(
        default=None, description="Exact feature flag id match."
    )
    role_id__eq: uuid.UUID | None = Field(default=None, description="Exact role id match.")
    created_at__gte: datetime | None = Field(
        default=None, description="ISO 8601; overrides created at or after."
    )
    created_at__lt: datetime | None = Field(
        default=None, description="ISO 8601; overrides created before."
    )
    created_at__gt: datetime | None = Field(
        default=None, description="ISO 8601; overrides created strictly after."
    )
    created_at__lte: datetime | None = Field(
        default=None, description="ISO 8601; overrides created at or before."
    )


class FeatureFlagRoleSearchResult(BaseModel):
    """Paginated collection of feature-flag role overrides."""

    items: list[FeatureFlagRoleRead]
    next_cursor: str | None = Field(
        default=None,
        description="Opaque cursor for the next page; null when no more results.",
    )
    limit: int


# Batch write: POST /feature-flag-roles/batch applies create/delete atomically
# (AGENTS.md §3). Overrides are immutable, so there is no update op; to change
# an override, delete and re-create within the same batch.


class FeatureFlagRoleBatchCreate(BaseModel):
    """Create operation within a feature-flag-role batch write."""

    op: Literal["create"] = "create"
    data: FeatureFlagRoleCreate


class FeatureFlagRoleBatchDelete(BaseModel):
    """Delete operation within a feature-flag-role batch write."""

    op: Literal["delete"] = "delete"
    id: uuid.UUID


FeatureFlagRoleBatchOp = Annotated[
    FeatureFlagRoleBatchCreate | FeatureFlagRoleBatchDelete,
    Field(discriminator="op"),
]


class FeatureFlagRoleBatchWriteRequest(BaseModel):
    """Request body for ``POST /feature-flag-roles/batch``."""

    operations: list[FeatureFlagRoleBatchOp] = Field(
        min_length=1,
        max_length=100,
        description="Operations to apply atomically; create/delete mixed (no update).",
    )


__all__ = [
    "EnabledFeatureFlags",
    "FeatureFlag",
    "FeatureFlagBatchWriteRequest",
    "FeatureFlagCreate",
    "FeatureFlagRead",
    "FeatureFlagRole",
    "FeatureFlagRoleBatchWriteRequest",
    "FeatureFlagRoleCreate",
    "FeatureFlagRoleRead",
    "FeatureFlagRoleSearchFilter",
    "FeatureFlagRoleSearchResult",
    "FeatureFlagSearchFilter",
    "FeatureFlagSearchResult",
    "FeatureFlagUpdate",
]
