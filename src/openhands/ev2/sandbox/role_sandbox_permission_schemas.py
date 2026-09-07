"""Pydantic schemas for the role-sandbox-permission grant feature.

Uniform REST surface (AGENTS.md §3): the collection is
``/role-sandbox-permissions`` with cursor pagination; create is ``POST``,
update is ``PATCH`` (the grant is mutable — toggle the read/update/delete
flags), retrieve is ``GET``, remove is ``DELETE``, plus batch read/write.
Mirrors ``role_secret_permission_schemas``.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from openhands.ev2.sandbox.sandbox_models import RoleSandboxPermission
from openhands.ev2.util.search_filter import BaseSearchFilter


class RoleSandboxPermissionCreate(BaseModel):
    """Payload to grant a role access to a sandbox."""

    model_config = ConfigDict(populate_by_name=True)

    role_id: uuid.UUID
    sandbox_id: uuid.UUID
    read_enabled: bool = False
    update_enabled: bool = False
    delete_enabled: bool = False


class RoleSandboxPermissionUpdate(BaseModel):
    """Partial update of a role-sandbox grant. All flags optional."""

    model_config = ConfigDict(populate_by_name=True)

    read_enabled: bool | None = None
    update_enabled: bool | None = None
    delete_enabled: bool | None = None


class RoleSandboxPermissionRead(BaseModel):
    """Role-sandbox grant representation returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    role_id: uuid.UUID
    sandbox_id: uuid.UUID
    read_enabled: bool
    update_enabled: bool
    delete_enabled: bool
    created_at: datetime
    updated_at: datetime


class RoleSandboxPermissionSearchFilter(BaseSearchFilter[RoleSandboxPermission]):
    """Optional filter clauses for ``GET /role-sandbox-permissions``."""

    role_id__eq: uuid.UUID | None = Field(default=None, description="Exact role id match.")
    sandbox_id__eq: uuid.UUID | None = Field(default=None, description="Exact sandbox id match.")
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


class RoleSandboxPermissionSearchResult(BaseModel):
    """Paginated collection of role-sandbox-permission grants."""

    items: list[RoleSandboxPermissionRead]
    next_cursor: str | None = Field(
        default=None,
        description="Opaque cursor for the next page; null when no more results.",
    )
    limit: int


class RoleSandboxPermissionBatchCreate(BaseModel):
    """Create operation within a role-sandbox-permission batch write."""

    op: Literal["create"] = "create"
    data: RoleSandboxPermissionCreate


class RoleSandboxPermissionBatchUpdate(BaseModel):
    """Update operation within a role-sandbox-permission batch write."""

    op: Literal["update"] = "update"
    id: uuid.UUID
    data: RoleSandboxPermissionUpdate


class RoleSandboxPermissionBatchDelete(BaseModel):
    """Delete operation within a role-sandbox-permission batch write."""

    op: Literal["delete"] = "delete"
    id: uuid.UUID


RoleSandboxPermissionBatchOp = Annotated[
    RoleSandboxPermissionBatchCreate
    | RoleSandboxPermissionBatchUpdate
    | RoleSandboxPermissionBatchDelete,
    Field(discriminator="op"),
]


class RoleSandboxPermissionBatchWriteRequest(BaseModel):
    """Request body for ``POST /role-sandbox-permissions/batch``."""

    operations: list[RoleSandboxPermissionBatchOp] = Field(
        min_length=1,
        max_length=100,
        description="Operations to apply atomically; create/update/delete mixed.",
    )
