"""Pydantic schemas for the permission feature."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from ohev.permission.models.permission import Action, SelectorKind


class PermissionCreate(BaseModel):
    """Payload to create a permission."""

    model_config = ConfigDict(populate_by_name=True)

    user_id: uuid.UUID
    action: Action = Action.READ
    custom_action: str | None = Field(
        default=None,
        description="Literal verb for non-CRUD actions (e.g. 'use').",
        max_length=64,
    )
    resource_type: str = Field(..., max_length=64)
    selector_kind: SelectorKind = SelectorKind.ALL
    selector_value: str | None = Field(default=None, max_length=255)
    attributes: list[str] | None = None


class PermissionUpdate(BaseModel):
    """Partial update of a permission. All fields optional."""

    action: Action | None = None
    custom_action: str | None = None
    resource_type: str | None = Field(default=None, max_length=64)
    selector_kind: SelectorKind | None = None
    selector_value: str | None = Field(default=None, max_length=255)
    attributes: list[str] | None = None


class PermissionRead(BaseModel):
    """Permission representation returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    user_id: uuid.UUID
    action: Action
    custom_action: str | None
    resource_type: str
    selector_kind: SelectorKind
    selector_value: str | None
    attributes: list[str] | None
    created_at: datetime
    updated_at: datetime


class PermissionList(BaseModel):
    """Paginated collection of permissions."""

    items: list[PermissionRead]
    next_cursor: str | None = None
    limit: int
