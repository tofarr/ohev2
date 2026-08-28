"""Pydantic schemas for the user-role assignment feature.

Uniform REST surface (AGENTS.md §3): the collection is ``/user-roles`` with
cursor pagination; create is ``POST``, retrieve is ``GET``, and remove is
``DELETE``. Assignments are immutable (no ``PATCH``) — to change an
assignment, delete and re-create, mirroring the CORS allow-list.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from openhands.ev2.role.role_models import UserRole
from openhands.ev2.util.search_filter import BaseSearchFilter


class UserRoleCreate(BaseModel):
    """Payload to assign a role to a user."""

    model_config = ConfigDict(populate_by_name=True)

    role_id: uuid.UUID
    user_id: uuid.UUID


class UserRoleRead(BaseModel):
    """User-role assignment representation returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    role_id: uuid.UUID
    user_id: uuid.UUID
    created_at: datetime


class UserRoleSearchFilter(BaseSearchFilter[UserRole]):
    """Optional filter clauses for `GET /user-roles`.

    Field names follow the `<attr>__<op>` convention so the base class derives
    both the in-memory `matches` predicate and the SQL `filter_sql` clauses
    automatically. Every field is optional; an unset filter matches everything.
    """

    role_id__eq: uuid.UUID | None = Field(default=None, description="Exact role id match.")
    user_id__eq: uuid.UUID | None = Field(default=None, description="Exact user id match.")
    created_at__gte: datetime | None = Field(
        default=None, description="ISO 8601; assignments created at or after."
    )
    created_at__lt: datetime | None = Field(
        default=None, description="ISO 8601; assignments created before."
    )
    created_at__gt: datetime | None = Field(
        default=None, description="ISO 8601; assignments created strictly after."
    )
    created_at__lte: datetime | None = Field(
        default=None, description="ISO 8601; assignments created at or before."
    )


class UserRoleSearchResult(BaseModel):
    """Paginated collection of user-role assignments."""

    items: list[UserRoleRead]
    next_cursor: str | None = Field(
        default=None,
        description="Opaque cursor for the next page; null when no more results.",
    )
    limit: int
