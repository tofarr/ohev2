"""Pydantic schemas for the role-sandbox-template-permission grant feature.

Uniform REST surface (AGENTS.md §3): the collection is
``/role-sandbox-template-permissions`` with cursor pagination; create is
``POST``, update is ``PATCH`` (the grant is mutable — toggle the
read/update/delete flags), retrieve is ``GET``, remove is ``DELETE``, plus
batch read/write. Mirrors ``role_secret_permission_schemas``.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from openhands.ev2.sandbox_v2.role_sandbox_template_permission_models import (
    RoleSandboxTemplatePermission,
)
from openhands.ev2.util.search_filter import BaseSearchFilter


class RoleSandboxTemplatePermissionCreate(BaseModel):
    """Payload to grant a role access to a sandbox template."""

    model_config = ConfigDict(populate_by_name=True)

    role_id: uuid.UUID
    sandbox_template_id: uuid.UUID
    read_enabled: bool = False
    update_enabled: bool = False
    delete_enabled: bool = False


class RoleSandboxTemplatePermissionUpdate(BaseModel):
    """Partial update of a role-sandbox-template grant. All flags optional."""

    model_config = ConfigDict(populate_by_name=True)

    read_enabled: bool | None = None
    update_enabled: bool | None = None
    delete_enabled: bool | None = None


class RoleSandboxTemplatePermissionRead(BaseModel):
    """Role-sandbox-template grant representation returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    role_id: uuid.UUID
    sandbox_template_id: uuid.UUID
    read_enabled: bool
    update_enabled: bool
    delete_enabled: bool
    created_at: datetime
    updated_at: datetime


class RoleSandboxTemplatePermissionSearchFilter(BaseSearchFilter[RoleSandboxTemplatePermission]):
    """Optional filter clauses for ``GET /role-sandbox-template-permissions``."""

    role_id__eq: uuid.UUID | None = Field(default=None, description="Exact role id match.")
    sandbox_template_id__eq: uuid.UUID | None = Field(
        default=None, description="Exact sandbox_template id match."
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


class RoleSandboxTemplatePermissionSearchResult(BaseModel):
    """Paginated collection of role-sandbox-template-permission grants."""

    items: list[RoleSandboxTemplatePermissionRead]
    next_cursor: str | None = Field(
        default=None,
        description="Opaque cursor for the next page; null when no more results.",
    )
    limit: int


class RoleSandboxTemplatePermissionBatchCreate(BaseModel):
    """Create operation within a role-sandbox-template-permission batch write."""

    op: Literal["create"] = "create"
    data: RoleSandboxTemplatePermissionCreate


class RoleSandboxTemplatePermissionBatchUpdate(BaseModel):
    """Update operation within a role-sandbox-template-permission batch write."""

    op: Literal["update"] = "update"
    id: uuid.UUID
    data: RoleSandboxTemplatePermissionUpdate


class RoleSandboxTemplatePermissionBatchDelete(BaseModel):
    """Delete operation within a role-sandbox-template-permission batch write."""

    op: Literal["delete"] = "delete"
    id: uuid.UUID


RoleSandboxTemplatePermissionBatchOp = Annotated[
    RoleSandboxTemplatePermissionBatchCreate
    | RoleSandboxTemplatePermissionBatchUpdate
    | RoleSandboxTemplatePermissionBatchDelete,
    Field(discriminator="op"),
]


class RoleSandboxTemplatePermissionBatchWriteRequest(BaseModel):
    """Request body for ``POST /role-sandbox-template-permissions/batch``."""

    operations: list[RoleSandboxTemplatePermissionBatchOp] = Field(
        min_length=1,
        max_length=100,
        description="Operations to apply atomically; create/update/delete mixed.",
    )
