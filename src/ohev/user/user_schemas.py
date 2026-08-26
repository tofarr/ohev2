"""Pydantic schemas for the user feature."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from ohev.user.user_models import User
from ohev.util.search_filter import BaseSearchFilter


class UserCreate(BaseModel):
    """Payload to create a user."""

    model_config = ConfigDict(populate_by_name=True)

    email: EmailStr
    username: str = Field(min_length=1, max_length=64)
    enabled: bool = True
    # Plaintext password received over the wire; hashed with bcrypt before
    # persistence. Never returned by the API (UserRead omits it).
    password: str | None = Field(default=None, min_length=1)

    @field_validator("username")
    @classmethod
    def _strip_username(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("username must be a non-empty string")
        return v


class UserUpdate(BaseModel):
    """Payload to partially update a user. All fields optional."""

    model_config = ConfigDict(populate_by_name=True)

    email: EmailStr | None = None
    username: str | None = Field(default=None, min_length=1, max_length=64)
    enabled: bool | None = None
    password: str | None = Field(default=None, min_length=1)

    @field_validator("username")
    @classmethod
    def _strip_username(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip()
        if not v:
            raise ValueError("username must be a non-empty string")
        return v


class UserRead(BaseModel):
    """User representation returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: EmailStr
    username: str
    enabled: bool
    created_at: datetime
    updated_at: datetime


class UserLogin(BaseModel):
    """Credentials submitted to the login endpoint."""

    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1)


class LoginResponse(BaseModel):
    """Successful login response; the auth token is also set as a cookie."""

    user: UserRead
    token_type: str = "bearer"


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
    username__contains: str | None = Field(
        default=None, description="Case-insensitive username substring."
    )
    username__eq: str | None = Field(default=None, description="Exact username match.")
    enabled__eq: bool | None = Field(default=None, description="Exact enabled match.")
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
