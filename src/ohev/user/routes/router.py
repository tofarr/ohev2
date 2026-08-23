"""HTTP routes for the user feature.

Follows the uniform REST surface (AGENTS.md §3): GET /users (paginated),
POST /users, GET/PATCH/DELETE /users/{id}. Handlers validate, call the
service, and serialize — no business logic here.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from ohev.db import get_session
from ohev.user.schemas import UserCreate, UserList, UserRead, UserUpdate
from ohev.user.services import (
    UserEmailConflictError,
    UserNotFoundError,
    UserService,
)

router = APIRouter(prefix="/users", tags=["users"])


def _cursor(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid cursor; expected a UUID.",
        ) from exc


SessionDep = Annotated[AsyncSession, Depends(get_session)]


@router.get("", response_model=UserList)
async def list_users(
    session: SessionDep,
    cursor: Annotated[str | None, Query(description="Opaque UUID cursor")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    email__contains: Annotated[
        str | None,
        Query(alias="email__contains", description="Case-insensitive email substring"),
    ] = None,
    created_at__gte: Annotated[
        datetime | None,
        Query(alias="created_at__gte", description="ISO 8601; users created at or after"),
    ] = None,
    created_at__lt: Annotated[
        datetime | None,
        Query(alias="created_at__lt", description="ISO 8601; users created before"),
    ] = None,
) -> UserList:
    service = UserService(session)
    cursor_uuid = _cursor(cursor) if cursor is not None else None
    users, next_cursor = await service.list_users(
        cursor=cursor_uuid,
        limit=limit,
        email_contains=email__contains,
        created_at_gte=created_at__gte,
        created_at_lt=created_at__lt,
    )
    return UserList(
        items=[UserRead.model_validate(u) for u in users],
        next_cursor=str(next_cursor) if next_cursor is not None else None,
        limit=limit,
    )


@router.post("", response_model=UserRead, status_code=status.HTTP_201_CREATED)
async def create_user(payload: UserCreate, session: SessionDep) -> UserRead:
    service = UserService(session)
    try:
        user = await service.create(payload)
    except UserEmailConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"User with email already exists: {exc}",
        ) from exc
    await session.commit()
    return UserRead.model_validate(user)


@router.get("/{user_id}", response_model=UserRead)
async def get_user(user_id: uuid.UUID, session: SessionDep) -> UserRead:
    service = UserService(session)
    try:
        user = await service.get(user_id)
    except UserNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User not found: {exc}",
        ) from exc
    return UserRead.model_validate(user)


@router.patch("/{user_id}", response_model=UserRead)
async def update_user(user_id: uuid.UUID, payload: UserUpdate, session: SessionDep) -> UserRead:
    service = UserService(session)
    try:
        user = await service.update(user_id, payload)
    except UserNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User not found: {exc}",
        ) from exc
    except UserEmailConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"User with email already exists: {exc}",
        ) from exc
    await session.commit()
    return UserRead.model_validate(user)


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(user_id: uuid.UUID, session: SessionDep) -> None:
    service = UserService(session)
    try:
        await service.delete(user_id)
    except UserNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User not found: {exc}",
        ) from exc
    await session.commit()
