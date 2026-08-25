"""Pydantic schemas for the permission feature."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from ohev.permission.models.permission import Action, Permission, ResourceType
from ohev.utilities.search_filter import BaseSearchFilter


class PermissionCreate(BaseModel):
    """Payload to create a permission. Permissions are immutable (no update)."""

    model_config = ConfigDict(populate_by_name=True)

    user_id: uuid.UUID
    action: Action = Action.READ
    resource_type: ResourceType
    attributes: list[str] | None = None


class PermissionRead(BaseModel):
    """Permission representation returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    user_id: uuid.UUID
    action: Action
    resource_type: ResourceType
    attributes: list[str] | None
    created_at: datetime


class PermissionSearchFilter(BaseSearchFilter[Permission]):
    """Optional filter clauses for `GET /permissions`.

    Field names follow the `<attr>__<op>` convention. Every field is optional;
    an unset filter matches everything. `user_id__eq` replaces the legacy
    `user_id` query param so filtering keys are uniform across resources
    (AGENTS.md §3).
    """

    user_id__eq: uuid.UUID | None = Field(default=None, description="Exact user id match.")
    action__eq: Action | None = Field(default=None, description="Exact action match.")
    resource_type__eq: ResourceType | None = Field(
        default=None, description="Exact resource type match."
    )
    created_at__gte: datetime | None = Field(
        default=None, description="ISO 8601; permissions created at or after."
    )
    created_at__lt: datetime | None = Field(
        default=None, description="ISO 8601; permissions created before."
    )
    created_at__gt: datetime | None = Field(
        default=None, description="ISO 8601; permissions created strictly after."
    )
    created_at__lte: datetime | None = Field(
        default=None, description="ISO 8601; permissions created at or before."
    )


class PermissionSearchResult(BaseModel):
    """Paginated collection of permissions."""

    items: list[PermissionRead]
    next_cursor: str | None = None
    limit: int = Field(default=50, ge=1, le=100)
