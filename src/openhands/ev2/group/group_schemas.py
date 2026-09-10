"""Pydantic schemas for the group feature.

Uniform REST surface (AGENTS.md §3). Two collections:

* ``/groups`` — full CRUD (GET paginated, POST, GET/{id}, PATCH/{id},
  DELETE/{id}) plus batch read/write and count. ``creator_id`` is not accepted
  on create/update: it is the authenticated principal and is set by the
  service.
* ``/group-users`` — immutable membership link rows (GET paginated, POST,
  GET/{id}, DELETE/{id}) plus batch read/write and count; no ``PATCH``.
  ``creator_id`` is the principal that added the member, set by the service.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from openhands.ev2.group.group_models import Group, GroupUser
from openhands.ev2.util.search_filter import BaseSearchFilter

# ---------------------------------------------------------------------- #
# Group
# ---------------------------------------------------------------------- #


class GroupCreate(BaseModel):
    """Payload to create a group. ``creator_id`` is set from the principal."""

    model_config = ConfigDict(populate_by_name=True)

    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=2048)

    @field_validator("name")
    @classmethod
    def _strip_name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("name must be a non-empty string")
        return v


class GroupUpdate(BaseModel):
    """Payload to partially update a group. All fields optional."""

    model_config = ConfigDict(populate_by_name=True)

    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=2048)

    @field_validator("name")
    @classmethod
    def _strip_name(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip()
        if not v:
            raise ValueError("name must be a non-empty string")
        return v


class GroupRead(BaseModel):
    """Group representation returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    description: str | None
    creator_id: uuid.UUID
    created_at: datetime
    updated_at: datetime


class GroupSearchFilter(BaseSearchFilter[Group]):
    """Optional filter clauses for `GET /groups`."""

    name__contains: str | None = Field(default=None, description="Case-insensitive name substring.")
    name__eq: str | None = Field(default=None, description="Exact name match.")
    creator_id__eq: uuid.UUID | None = Field(default=None, description="Exact creator id match.")
    created_at__gte: datetime | None = Field(
        default=None, description="ISO 8601; groups created at or after."
    )
    created_at__lt: datetime | None = Field(
        default=None, description="ISO 8601; groups created before."
    )
    created_at__gt: datetime | None = Field(
        default=None, description="ISO 8601; groups created strictly after."
    )
    created_at__lte: datetime | None = Field(
        default=None, description="ISO 8601; groups created at or before."
    )


class GroupSearchResult(BaseModel):
    """Paginated collection of groups."""

    items: list[GroupRead]
    next_cursor: str | None = Field(
        default=None,
        description="Opaque cursor for the next page; null when no more results.",
    )
    limit: int


class GroupBatchCreate(BaseModel):
    """Create operation within a group batch write."""

    op: Literal["create"] = "create"
    data: GroupCreate


class GroupBatchUpdate(BaseModel):
    """Update operation within a group batch write."""

    op: Literal["update"] = "update"
    id: uuid.UUID
    data: GroupUpdate


class GroupBatchDelete(BaseModel):
    """Delete operation within a group batch write."""

    op: Literal["delete"] = "delete"
    id: uuid.UUID


GroupBatchOp = Annotated[
    GroupBatchCreate | GroupBatchUpdate | GroupBatchDelete,
    Field(discriminator="op"),
]


class GroupBatchWriteRequest(BaseModel):
    """Request body for `POST /groups/batch`."""

    operations: list[GroupBatchOp] = Field(
        min_length=1,
        max_length=100,
        description="Operations to apply atomically; create/update/delete mixed.",
    )


# ---------------------------------------------------------------------- #
# GroupUser
# ---------------------------------------------------------------------- #


class GroupUserCreate(BaseModel):
    """Payload to add a user to a group. ``creator_id`` is set from the principal."""

    model_config = ConfigDict(populate_by_name=True)

    group_id: uuid.UUID
    user_id: uuid.UUID


class GroupUserRead(BaseModel):
    """Group-user membership representation returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    group_id: uuid.UUID
    user_id: uuid.UUID
    creator_id: uuid.UUID
    created_at: datetime


class GroupUserSearchFilter(BaseSearchFilter[GroupUser]):
    """Optional filter clauses for `GET /group-users`."""

    group_id__eq: uuid.UUID | None = Field(default=None, description="Exact group id match.")
    user_id__eq: uuid.UUID | None = Field(default=None, description="Exact user id match.")
    creator_id__eq: uuid.UUID | None = Field(default=None, description="Exact creator id match.")
    created_at__gte: datetime | None = Field(
        default=None, description="ISO 8601; memberships created at or after."
    )
    created_at__lt: datetime | None = Field(
        default=None, description="ISO 8601; memberships created before."
    )
    created_at__gt: datetime | None = Field(
        default=None, description="ISO 8601; memberships created strictly after."
    )
    created_at__lte: datetime | None = Field(
        default=None, description="ISO 8601; memberships created at or before."
    )


class GroupUserSearchResult(BaseModel):
    """Paginated collection of group-user memberships."""

    items: list[GroupUserRead]
    next_cursor: str | None = Field(
        default=None,
        description="Opaque cursor for the next page; null when no more results.",
    )
    limit: int


# Batch write: POST /group-users/batch applies create/delete atomically
# (AGENTS.md §3). Memberships are immutable, so there is no update op; to
# change a membership, delete and re-create within the same batch.


class GroupUserBatchCreate(BaseModel):
    """Create operation within a group-user batch write."""

    op: Literal["create"] = "create"
    data: GroupUserCreate


class GroupUserBatchDelete(BaseModel):
    """Delete operation within a group-user batch write."""

    op: Literal["delete"] = "delete"
    id: uuid.UUID


GroupUserBatchOp = Annotated[
    GroupUserBatchCreate | GroupUserBatchDelete,
    Field(discriminator="op"),
]


class GroupUserBatchWriteRequest(BaseModel):
    """Request body for `POST /group-users/batch`."""

    operations: list[GroupUserBatchOp] = Field(
        min_length=1,
        max_length=100,
        description="Operations to apply atomically; create/delete mixed (no update).",
    )
