"""Pydantic schemas for the per-user secret permission feature.

Uniform REST surface (AGENTS.md §3): the collection is
``/user-secret-permissions`` with cursor pagination; create is ``POST``, update
is ``PATCH`` (the grant is mutable — toggle the read/update/delete flags),
retrieve is ``GET``, remove is ``DELETE``, plus batch read/write.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from openhands.ev2.secret.secret_models import UserSecretPermission
from openhands.ev2.util.search_filter import BaseSearchFilter


class UserSecretPermissionCreate(BaseModel):
    """Payload to grant a user access to a secret."""

    model_config = ConfigDict(populate_by_name=True)

    user_id: uuid.UUID
    secret_id: uuid.UUID
    read_enabled: bool = False
    update_enabled: bool = False
    delete_enabled: bool = False


class UserSecretPermissionUpdate(BaseModel):
    """Partial update of a user-secret grant. All flags optional."""

    model_config = ConfigDict(populate_by_name=True)

    read_enabled: bool | None = None
    update_enabled: bool | None = None
    delete_enabled: bool | None = None


class UserSecretPermissionRead(BaseModel):
    """User-secret grant representation returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    user_id: uuid.UUID
    secret_id: uuid.UUID
    read_enabled: bool
    update_enabled: bool
    delete_enabled: bool
    created_at: datetime
    updated_at: datetime


class UserSecretPermissionSearchFilter(BaseSearchFilter[UserSecretPermission]):
    """Optional filter clauses for ``GET /user-secret-permissions``."""

    user_id__eq: uuid.UUID | None = Field(default=None, description="Exact user id match.")
    secret_id__eq: uuid.UUID | None = Field(default=None, description="Exact secret id match.")
    read_enabled__eq: bool | None = Field(default=None, description="Exact read_enabled match.")
    update_enabled__eq: bool | None = Field(default=None, description="Exact update_enabled match.")
    delete_enabled__eq: bool | None = Field(default=None, description="Exact delete_enabled match.")
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


class UserSecretPermissionSearchResult(BaseModel):
    """Paginated collection of user-secret grants."""

    items: list[UserSecretPermissionRead]
    next_cursor: str | None = Field(
        default=None,
        description="Opaque cursor for the next page; null when no more results.",
    )
    limit: int


class UserSecretPermissionBatchCreate(BaseModel):
    """Create operation within a user-secret-permission batch write."""

    op: Literal["create"] = "create"
    data: UserSecretPermissionCreate


class UserSecretPermissionBatchUpdate(BaseModel):
    """Update operation within a user-secret-permission batch write."""

    op: Literal["update"] = "update"
    id: uuid.UUID
    data: UserSecretPermissionUpdate


class UserSecretPermissionBatchDelete(BaseModel):
    """Delete operation within a user-secret-permission batch write."""

    op: Literal["delete"] = "delete"
    id: uuid.UUID


UserSecretPermissionBatchOp = Annotated[
    UserSecretPermissionBatchCreate
    | UserSecretPermissionBatchUpdate
    | UserSecretPermissionBatchDelete,
    Field(discriminator="op"),
]


class UserSecretPermissionBatchWriteRequest(BaseModel):
    """Request body for ``POST /user-secret-permissions/batch``."""

    operations: list[UserSecretPermissionBatchOp] = Field(
        min_length=1,
        max_length=100,
        description="Operations to apply atomically; create/update/delete mixed.",
    )
