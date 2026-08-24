"""Pydantic schemas for the permission feature."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from ohev.permission.models.permission import Action, ResourceType


class PermissionCreate(BaseModel):
    """Payload to create a permission. Permissions are immutable (no update)."""

    model_config = ConfigDict(populate_by_name=True)

    user_id: uuid.UUID
    action: Action = Action.READ
    type: ResourceType
    attributes: list[str] | None = None


class PermissionRead(BaseModel):
    """Permission representation returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    user_id: uuid.UUID
    action: Action
    type: ResourceType
    attributes: list[str] | None
    created_at: datetime


class PermissionSearchResult(BaseModel):
    """Paginated collection of permissions."""

    items: list[PermissionRead]
    next_cursor: str | None = None
    limit: int = Field(default=50, ge=1, le=100)
