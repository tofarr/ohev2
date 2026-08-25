"""Pydantic schemas for the user feature."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from ohev.user.models.user import User
from ohev.utilities.search_filter import BaseSearchFilter


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


class UserSearchFilter(BaseSearchFilter[User]):
    """Optional filter clauses for `GET /users`.

    Field names follow the `<attr>__<op>` convention so the base class derives
    both the in-memory `matches` predicate and the SQL `filter_sql` clauses
    automatically. Every field is optional; an unset filter matches everything.
    """

    email__contains: str | None = Field(
        default=None, description="Case-insensitive email substring."
    )
    email__eq: EmailStr | None = Field(default=None, description="Exact email match.")
    created_at__gte: datetime | None = Field(
        default=None, description="ISO 8601; users created at or after."
    )
    created_at__lt: datetime | None = Field(
        default=None, description="ISO 8601; users created before."
    )
    created_at__gt: datetime | None = Field(
        default=None, description="ISO 8601; users created strictly after."
    )
    created_at__lte: datetime | None = Field(
        default=None, description="ISO 8601; users created at or before."
    )


class UserSearchResult(BaseModel):
    """Paginated collection of users."""

    items: list[UserRead]
    next_cursor: str | None = Field(
        default=None,
        description="Opaque cursor for the next page; null when no more results.",
    )
    limit: int
