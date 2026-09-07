"""Pydantic schemas for the role-sandbox-snapshot-permission grant feature.

Uniform REST surface (AGENTS.md §3): the collection is
``/role-sandbox-snapshot-permissions`` with cursor pagination; create is
``POST``, update is ``PATCH`` (the grant is mutable — toggle the
read/update/delete flags), retrieve is ``GET``, remove is ``DELETE``, plus
batch read/write. Mirrors ``role_secret_permission_schemas``.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from openhands.ev2.sandbox.sandbox_models import RoleSandboxSnapshotPermission
from openhands.ev2.util.search_filter import BaseSearchFilter


class RoleSandboxSnapshotPermissionCreate(BaseModel):
    """Payload to grant a role access to a sandbox snapshot."""

    model_config = ConfigDict(populate_by_name=True)

    role_id: uuid.UUID
    sandbox_snapshot_id: uuid.UUID
    read_enabled: bool = False
    update_enabled: bool = False
    delete_enabled: bool = False


class RoleSandboxSnapshotPermissionUpdate(BaseModel):
    """Partial update of a role-sandbox-snapshot grant. All flags optional."""

    model_config = ConfigDict(populate_by_name=True)

    read_enabled: bool | None = None
    update_enabled: bool | None = None
    delete_enabled: bool | None = None


class RoleSandboxSnapshotPermissionRead(BaseModel):
    """Role-sandbox-snapshot grant representation returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    role_id: uuid.UUID
    sandbox_snapshot_id: uuid.UUID
    read_enabled: bool
    update_enabled: bool
    delete_enabled: bool
    created_at: datetime
    updated_at: datetime


class RoleSandboxSnapshotPermissionSearchFilter(BaseSearchFilter[RoleSandboxSnapshotPermission]):
    """Optional filter clauses for ``GET /role-sandbox-snapshot-permissions``."""

    role_id__eq: uuid.UUID | None = Field(default=None, description="Exact role id match.")
    sandbox_snapshot_id__eq: uuid.UUID | None = Field(
        default=None, description="Exact sandbox_snapshot id match."
    )
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


class RoleSandboxSnapshotPermissionSearchResult(BaseModel):
    """Paginated collection of role-sandbox-snapshot-permission grants."""

    items: list[RoleSandboxSnapshotPermissionRead]
    next_cursor: str | None = Field(
        default=None,
        description="Opaque cursor for the next page; null when no more results.",
    )
    limit: int


class RoleSandboxSnapshotPermissionBatchCreate(BaseModel):
    """Create operation within a role-sandbox-snapshot-permission batch write."""

    op: Literal["create"] = "create"
    data: RoleSandboxSnapshotPermissionCreate


class RoleSandboxSnapshotPermissionBatchUpdate(BaseModel):
    """Update operation within a role-sandbox-snapshot-permission batch write."""

    op: Literal["update"] = "update"
    id: uuid.UUID
    data: RoleSandboxSnapshotPermissionUpdate


class RoleSandboxSnapshotPermissionBatchDelete(BaseModel):
    """Delete operation within a role-sandbox-snapshot-permission batch write."""

    op: Literal["delete"] = "delete"
    id: uuid.UUID


RoleSandboxSnapshotPermissionBatchOp = Annotated[
    RoleSandboxSnapshotPermissionBatchCreate
    | RoleSandboxSnapshotPermissionBatchUpdate
    | RoleSandboxSnapshotPermissionBatchDelete,
    Field(discriminator="op"),
]


class RoleSandboxSnapshotPermissionBatchWriteRequest(BaseModel):
    """Request body for ``POST /role-sandbox-snapshot-permissions/batch``."""

    operations: list[RoleSandboxSnapshotPermissionBatchOp] = Field(
        min_length=1,
        max_length=100,
        description="Operations to apply atomically; create/update/delete mixed.",
    )
