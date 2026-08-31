"""Schemas for role-to-MCP-server-config grants."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from openhands.ev2.mcp_server_config.mcp_server_config_models import (
    RoleMCPServerConfigPermission,
)
from openhands.ev2.util.search_filter import BaseSearchFilter


class RoleMCPServerConfigPermissionCreate(BaseModel):
    """Payload to grant a role access to an MCP server configuration."""

    model_config = ConfigDict(populate_by_name=True)

    role_id: uuid.UUID
    mcp_server_config_id: uuid.UUID
    read_enabled: bool = False
    update_enabled: bool = False
    delete_enabled: bool = False


class RoleMCPServerConfigPermissionUpdate(BaseModel):
    """Partial update of a role-MCP-server-config grant."""

    model_config = ConfigDict(populate_by_name=True)

    read_enabled: bool | None = None
    update_enabled: bool | None = None
    delete_enabled: bool | None = None


class RoleMCPServerConfigPermissionRead(BaseModel):
    """Role-MCP-server-config grant representation returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    role_id: uuid.UUID
    mcp_server_config_id: uuid.UUID
    read_enabled: bool
    update_enabled: bool
    delete_enabled: bool
    created_at: datetime
    updated_at: datetime


class RoleMCPServerConfigPermissionSearchFilter(BaseSearchFilter[RoleMCPServerConfigPermission]):
    """Optional filter clauses for ``GET /role-mcp-server-config-permissions``."""

    role_id__eq: uuid.UUID | None = Field(default=None)
    mcp_server_config_id__eq: uuid.UUID | None = Field(default=None)
    read_enabled__eq: bool | None = Field(default=None)
    update_enabled__eq: bool | None = Field(default=None)
    delete_enabled__eq: bool | None = Field(default=None)
    created_at__gte: datetime | None = Field(default=None)
    created_at__lt: datetime | None = Field(default=None)
    created_at__gt: datetime | None = Field(default=None)
    created_at__lte: datetime | None = Field(default=None)


class RoleMCPServerConfigPermissionSearchResult(BaseModel):
    """Paginated collection of role-MCP-server-config grants."""

    items: list[RoleMCPServerConfigPermissionRead]
    next_cursor: str | None = Field(default=None)
    limit: int


class RoleMCPServerConfigPermissionBatchCreate(BaseModel):
    """Create operation within a role-MCP-server-config batch write."""

    op: Literal["create"] = "create"
    data: RoleMCPServerConfigPermissionCreate


class RoleMCPServerConfigPermissionBatchUpdate(BaseModel):
    """Update operation within a role-MCP-server-config batch write."""

    op: Literal["update"] = "update"
    id: uuid.UUID
    data: RoleMCPServerConfigPermissionUpdate


class RoleMCPServerConfigPermissionBatchDelete(BaseModel):
    """Delete operation within a role-MCP-server-config batch write."""

    op: Literal["delete"] = "delete"
    id: uuid.UUID


RoleMCPServerConfigPermissionBatchOp = Annotated[
    RoleMCPServerConfigPermissionBatchCreate
    | RoleMCPServerConfigPermissionBatchUpdate
    | RoleMCPServerConfigPermissionBatchDelete,
    Field(discriminator="op"),
]


class RoleMCPServerConfigPermissionBatchWriteRequest(BaseModel):
    """Request body for ``POST /role-mcp-server-config-permissions/batch``."""

    operations: list[RoleMCPServerConfigPermissionBatchOp] = Field(min_length=1, max_length=100)
