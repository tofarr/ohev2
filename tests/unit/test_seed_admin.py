"""Unit tests for the admin seed script (DB-backed)."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.permission.permission_models import Action, Permission, ResourceType
from openhands.ev2.scripts.seed_admin import seed_admin
from openhands.ev2.user.user_models import User
from openhands.ev2.util.password import verify_password


class TestSeedAdmin:
    async def test_seeds_user_and_permissions(self, session: AsyncSession) -> None:
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

        grants = await _admin_grants(session, user.id)
        assert {g.resource_type for g in grants} == set(ResourceType)
        for grant in grants:
            assert grant.action is Action.ALL
            assert grant.attributes is None
            assert grant.search_filter is None

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

        grants = await _admin_grants(session, user.id)
        assert len(grants) == len(set(ResourceType))

    async def test_backfills_new_resource_types(self, session: AsyncSession) -> None:
        """A pre-existing partial grant set is completed on re-seed."""
        user = await seed_admin(
            session,
            username="root",
            email="root@example.com",
            password="pw",
        )
        # Simulate a new resource type added after the first seed by deleting one
        # grant; re-running should recreate exactly it.
        grant = await session.scalar(
            select(Permission).where(
                Permission.user_id == user.id,
                Permission.resource_type == ResourceType.USER,
            )
        )
        assert grant is not None
        await session.delete(grant)
        await session.commit()

        await seed_admin(
            session,
            username="root",
            email="root@example.com",
            password="pw",
        )

        grants = await _admin_grants(session, user.id)
        assert {g.resource_type for g in grants} == set(ResourceType)

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


async def _admin_grants(
    session: AsyncSession,
    user_id: uuid.UUID,
) -> list[Permission]:
    stmt = select(Permission).where(
        Permission.user_id == user_id,
        Permission.action == Action.ALL,
    )
    result = await session.execute(stmt)
    return list(result.scalars().all())
