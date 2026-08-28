"""Pydantic schemas for the role feature.

Uniform REST surface (AGENTS.md §3): the collection is ``/roles`` with cursor
pagination; create is ``POST``, update is ``PATCH``, retrieve is ``GET``, and
remove is ``DELETE``. A role bundles per-resource permission policies stored as
a JSONB ``{resource_type: Permission}`` map (see ``security_models.Role``).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from openhands.ev2.security.security_models import Permission, Role
from openhands.ev2.util.search_filter import BaseSearchFilter


class RoleCreate(BaseModel):
    """Payload to create a role."""

    model_config = ConfigDict(populate_by_name=True)

    name: str = Field(min_length=1, max_length=255)
    policies: dict[str, Permission] | None = Field(
        default=None,
        description="Map of resource-type name -> Permission policy; missing key = deny.",
    )
    role_permission: Permission | None = Field(
        default=None,
        description="Permission policy for role/permission resources; null = deny.",
    )
    user_permission: Permission | None = Field(
        default=None,
        description="Permission policy for user resources; null = deny.",
    )

    @field_validator("name")
    @classmethod
    def _strip_name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("name must be a non-empty string")
        return v


class RoleUpdate(BaseModel):
    """Payload to partially update a role. All fields optional."""

    model_config = ConfigDict(populate_by_name=True)

    name: str | None = Field(default=None, min_length=1, max_length=255)
    policies: dict[str, Permission] | None = Field(
        default=None,
        description="Map of resource-type name -> Permission policy; missing key = deny.",
    )
    role_permission: Permission | None = Field(
        default=None,
        description="Permission policy for role/permission resources; null = deny.",
    )
    user_permission: Permission | None = Field(
        default=None,
        description="Permission policy for user resources; null = deny.",
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


class RoleRead(BaseModel):
    """Role representation returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    policies: dict[str, Permission] | None
    role_permission: Permission | None
    user_permission: Permission | None
    created_at: datetime
    updated_at: datetime


class RoleSearchFilter(BaseSearchFilter[Role]):
    """Optional filter clauses for `GET /roles`.

    Field names follow the `<attr>__<op>` convention so the base class derives
    both the in-memory `matches` predicate and the SQL `filter_sql` clauses
    automatically. Every field is optional; an unset filter matches everything.
    """

    name__contains: str | None = Field(default=None, description="Case-insensitive name substring.")
    name__eq: str | None = Field(default=None, description="Exact name match.")
    created_at__gte: datetime | None = Field(
        default=None, description="ISO 8601; roles created at or after."
    )
    created_at__lt: datetime | None = Field(
        default=None, description="ISO 8601; roles created before."
    )
    created_at__gt: datetime | None = Field(
        default=None, description="ISO 8601; roles created strictly after."
    )
    created_at__lte: datetime | None = Field(
        default=None, description="ISO 8601; roles created at or before."
    )


class RoleSearchResult(BaseModel):
    """Paginated collection of roles."""

    items: list[RoleRead]
    next_cursor: str | None = Field(
        default=None,
        description="Opaque cursor for the next page; null when no more results.",
    )
    limit: int
