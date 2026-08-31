"""DB-backed tests for the role models (Role and UserRole).

Verifies the per-entity ``Permission`` JSONB columns on :class:`Role`
round-trip through Postgres via :class:`PermissionType`, and that the
:class:`UserRole` link table persists with selectin relationships resolving.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.role.role_models import ROLE_ENTITY_COLUMNS, Role, UserRole
from openhands.ev2.security.security_models import Permitted, ReadOnly
from openhands.ev2.user.user_models import User


class TestRoleModel:
    """DB-backed persistence of Role with per-entity Permission JSONB columns."""

    async def test_role_persists_permission_columns(self, session: AsyncSession) -> None:
        role = Role(
            name="admin",
            role_permission=Permitted(),
            user_permission=Permitted(),
        )
        session.add(role)
        await session.flush()
        await session.refresh(role)

        assert isinstance(role.id, uuid.UUID)
        assert role.name == "admin"
        assert isinstance(role.role_permission, Permitted)
        assert isinstance(role.user_permission, Permitted)

    async def test_role_nullable_permission_columns(self, session: AsyncSession) -> None:
        role = Role(name="empty")
        session.add(role)
        await session.flush()
        await session.refresh(role)
        for column in ROLE_ENTITY_COLUMNS:
            assert getattr(role, column) is None

    async def test_role_permission_round_trips_concrete_subclass(
        self, session: AsyncSession
    ) -> None:
        role = Role(name="viewer", user_permission=ReadOnly())
        session.add(role)
        await session.flush()
        await session.refresh(role)
        # The TypeDecorator must restore the concrete ReadOnly subclass.
        assert isinstance(role.user_permission, ReadOnly)

    async def test_role_name_unique(self, session: AsyncSession) -> None:
        session.add(Role(name="dup"))
        await session.flush()
        session.add(Role(name="dup"))
        with pytest.raises(Exception):  # noqa: B017 — IntegrityError subclass
            await session.flush()


class TestUserRoleModel:
    """DB-backed persistence of the UserRole link table."""

    async def test_assign_role_to_user(self, session: AsyncSession) -> None:
        user = User(email="ru@example.com", username="ru")
        role = Role(name="viewer", user_permission=ReadOnly())
        session.add(user)
        session.add(role)
        await session.flush()

        link = UserRole(role_id=role.id, user_id=user.id)
        session.add(link)
        await session.flush()
        await session.refresh(link)

        assert isinstance(link.id, uuid.UUID)
        assert link.role_id == role.id
        assert link.user_id == user.id
        # selectin relationships resolve to the linked rows.
        assert link.role.name == "viewer"
        assert link.user.email == "ru@example.com"

    async def test_user_role_query_by_user(self, session: AsyncSession) -> None:
        user = User(email="qu@example.com", username="qu")
        role = Role(name="admin", user_permission=Permitted())
        session.add(user)
        session.add(role)
        await session.flush()
        session.add(UserRole(role_id=role.id, user_id=user.id))
        await session.flush()

        stmt = select(UserRole).where(UserRole.user_id == user.id)
        links = list((await session.execute(stmt)).scalars().all())
        assert len(links) == 1
        assert isinstance(links[0].role.user_permission, Permitted)
