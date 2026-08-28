"""Shared helpers for role-based authorization in route tests."""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.role.role_models import Role, UserRole
from openhands.ev2.security.security_models import Permission
from openhands.ev2.user.user_models import User
from openhands.ev2.user.user_schemas import UserCreate
from openhands.ev2.user.user_service import UserService
from openhands.ev2.util.search_filter import AllSearchFilter


async def make_principal(
    session: AsyncSession,
    *,
    email: str,
    username: str,
    password: str | None = None,
) -> User:
    """Create a user directly in the DB (bypassing the permission-guarded API)."""
    return await UserService(session, AllSearchFilter[User]()).create(
        UserCreate(email=email, username=username, password=password)
    )


async def assign_role(
    session: AsyncSession,
    user_id: uuid.UUID,
    permissions: dict[str, Permission | None],
    *,
    role_name: str | None = None,
) -> Role:
    """Create (or reuse) a role with *permissions* and assign it to *user_id*.

    *permissions* maps a Role per-entity ``Permission`` column name (e.g.
    ``"user_permission"``) to its policy. Each call creates a fresh role so
    per-test policy isolation is preserved.
    """
    name = role_name or f"role-{user_id}-{len(permissions)}"
    role = Role(name=name, **dict(permissions))
    session.add(role)
    await session.flush()
    session.add(UserRole(role_id=role.id, user_id=user_id))
    await session.flush()
    return role


async def roles_for(session: AsyncSession, user_id: uuid.UUID) -> list[Role]:
    """Return the roles assigned to *user_id*."""
    stmt = (
        select(Role).join(UserRole, UserRole.role_id == Role.id).where(UserRole.user_id == user_id)
    )
    return list((await session.execute(stmt)).scalars().all())
