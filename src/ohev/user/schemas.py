"""Pydantic schemas for the user feature."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserCreate(BaseModel):
    """Payload to create a user."""

    model_config = ConfigDict(populate_by_name=True)

    email: EmailStr


class UserUpdate(BaseModel):
    """Payload to partially update a user. All fields optional."""

    email: EmailStr | None = None


class UserRead(BaseModel):
    """User representation returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: EmailStr
    created_at: datetime
    updated_at: datetime


class UserList(BaseModel):
    """Paginated collection of users."""

    items: list[UserRead]
    next_cursor: str | None = Field(
        default=None,
        description="Opaque cursor for the next page; null when no more results.",
    )
    limit: int
