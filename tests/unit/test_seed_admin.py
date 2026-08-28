"""Unit tests for the admin seed script (DB-backed)."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.scripts.seed_admin import _ADMIN_RESOURCE_TYPES, seed_admin
from openhands.ev2.security.security_models import Permitted, Role, RoleUser
from openhands.ev2.user.user_models import User
from openhands.ev2.util.password import verify_password


class TestSeedAdmin:
    async def test_seeds_user_and_admin_role(self, session: AsyncSession) -> None:
        user = await seed_admin(
            session,
            username="root",
            email="root@example.com",
            password="s3cret!",
        )

        assert isinstance(user.id, uuid.UUID)
        assert user.username == "root"
        assert user.email == "root@example.com"
        assert user.enabled is True
        # Password is hashed, never plaintext, and verifies.
        assert user.password is not None
        assert user.password != "s3cret!"
        assert verify_password("s3cret!", user.password)

        role = await _admin_role(session, user.id)
        assert role.name == "admin"
        assert set(role.policies.keys()) == set(_ADMIN_RESOURCE_TYPES)
        for policy in role.policies.values():
            assert isinstance(policy, Permitted)

    async def test_rerun_is_idempotent(self, session: AsyncSession) -> None:
        await seed_admin(
            session,
            username="root",
            email="root@example.com",
            password="first",
        )
        # Second run with a new password/email — must update, not duplicate.
        user = await seed_admin(
            session,
            username="root",
            email="changed@example.com",
            password="second",
        )

        assert user.email == "changed@example.com"
        assert user.password is not None
        assert verify_password("second", user.password)
        assert not verify_password("first", user.password)

        users = await session.scalars(select(User).where(User.username == "root"))
        assert len(users.all()) == 1

        # Exactly one admin role, assigned once.
        roles = await session.scalars(select(Role).where(Role.name == "admin"))
        assert len(roles.all()) == 1
        memberships = await session.scalars(select(RoleUser).where(RoleUser.user_id == user.id))
        assert len(memberships.all()) == 1

    async def test_backfills_new_resource_types(self, session: AsyncSession) -> None:
        """A missing policies entry is restored on re-seed."""
        user = await seed_admin(
            session,
            username="root",
            email="root@example.com",
            password="pw",
        )
        role = await _admin_role(session, user.id)
        # Simulate a new resource type added after the first seed by dropping one
        # policies entry; re-running should restore it.
        role.policies = {k: v for k, v in role.policies.items() if k != "user"}
        await session.commit()

        await seed_admin(
            session,
            username="root",
            email="root@example.com",
            password="pw",
        )

        role = await _admin_role(session, user.id)
        assert set(role.policies.keys()) == set(_ADMIN_RESOURCE_TYPES)

    async def test_invalid_email_raises(self, session: AsyncSession) -> None:
        with pytest.raises(ValueError, match="invalid email"):
            await seed_admin(
                session,
                username="root",
                email="not-an-email",
                password="pw",
            )

    async def test_empty_username_raises(self, session: AsyncSession) -> None:
        with pytest.raises(ValueError, match="username"):
            await seed_admin(
                session,
                username="   ",
                email="root@example.com",
                password="pw",
            )

    async def test_empty_password_raises(self, session: AsyncSession) -> None:
        with pytest.raises(ValueError, match="password"):
            await seed_admin(
                session,
                username="root",
                email="root@example.com",
                password="",
            )


async def _admin_role(session: AsyncSession, user_id: uuid.UUID) -> Role:
    """The admin role assigned to *user_id*."""
    stmt = (
        select(Role).join(RoleUser, RoleUser.role_id == Role.id).where(RoleUser.user_id == user_id)
    )
    role = await session.scalar(stmt)
    assert role is not None, "admin role not assigned to user"
    return role
