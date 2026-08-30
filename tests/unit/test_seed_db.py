"""Unit tests for the database seed script (DB-backed)."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.api_key.api_key_security import ApiKeyAccess, ApiKeyAccessFilter
from openhands.ev2.role.role_models import ROLE_ENTITY_COLUMNS, Role, UserRole
from openhands.ev2.scripts.seed_db import seed_admin, seed_db
from openhands.ev2.security.security_models import Action, Permitted
from openhands.ev2.user.user_models import User
from openhands.ev2.util.password import verify_password

_ADMIN_COLUMNS = ROLE_ENTITY_COLUMNS


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
        for column in _ADMIN_COLUMNS:
            assert isinstance(getattr(role, column), Permitted)
        # The regular-user role is also seeded.
        user_role = await _named_role(session, "user")
        assert isinstance(user_role.api_key_permission, ApiKeyAccess)

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
        memberships = await session.scalars(select(UserRole).where(UserRole.user_id == user.id))
        assert len(memberships.all()) == 1

    async def test_backfills_new_resource_types(self, session: AsyncSession) -> None:
        """A dropped per-entity column is restored on re-seed."""
        user = await seed_admin(
            session,
            username="root",
            email="root@example.com",
            password="pw",
        )
        role = await _admin_role(session, user.id)
        # Simulate a missing grant by clearing one column; re-running restores it.
        role.user_permission = None
        await session.commit()

        await seed_admin(
            session,
            username="root",
            email="root@example.com",
            password="pw",
        )

        role = await _admin_role(session, user.id)
        assert isinstance(role.user_permission, Permitted)

    async def test_invalid_email_raises(self, session: AsyncSession) -> None:
        with pytest.raises(ValueError, match="invalid admin email"):
            await seed_admin(
                session,
                username="root",
                email="not-an-email",
                password="pw",
            )

    async def test_empty_username_raises(self, session: AsyncSession) -> None:
        with pytest.raises(ValueError, match="admin username"):
            await seed_admin(
                session,
                username="   ",
                email="root@example.com",
                password="pw",
            )

    async def test_empty_password_raises(self, session: AsyncSession) -> None:
        with pytest.raises(ValueError, match="admin password"):
            await seed_admin(
                session,
                username="root",
                email="root@example.com",
                password="",
            )


class TestSeedDbRegularUser:
    async def test_seeds_regular_user_with_user_role(self, session: AsyncSession) -> None:
        admin, regular = await seed_db(
            session,
            admin_username="root",
            admin_email="root@example.com",
            admin_password="pw",
            user_username="joe",
            user_email="joe@example.com",
            user_password="pw",
        )
        assert admin.username == "root"
        assert regular is not None
        assert regular.username == "joe"
        assert verify_password("pw", regular.password)

        user_role = await _named_role(session, "user")
        assert isinstance(user_role.api_key_permission, ApiKeyAccess)
        # Every other entity column is denied (None).
        for col in _ADMIN_COLUMNS:
            if col == "api_key_permission":
                continue
            assert getattr(user_role, col) is None
        # The regular user is a member of the user role.
        membership = await session.scalar(select(UserRole).where(UserRole.user_id == regular.id))
        assert membership is not None
        assert membership.role_id == user_role.id

    async def test_user_role_rerun_is_idempotent(self, session: AsyncSession) -> None:
        await seed_db(
            session,
            admin_username="root",
            admin_email="root@example.com",
            admin_password="pw",
            user_username="joe",
            user_email="joe@example.com",
            user_password="first",
        )
        await seed_db(
            session,
            admin_username="root",
            admin_email="root@example.com",
            admin_password="pw",
            user_username="joe",
            user_email="joe@example.com",
            user_password="second",
        )
        roles = await session.scalars(select(Role).where(Role.name == "user"))
        assert len(roles.all()) == 1
        user_role = await _named_role(session, "user")
        assert isinstance(user_role.api_key_permission, ApiKeyAccess)

    async def test_user_role_backfills_api_key_permission(self, session: AsyncSession) -> None:
        await seed_db(
            session,
            admin_username="root",
            admin_email="root@example.com",
            admin_password="pw",
            user_username="joe",
            user_email="joe@example.com",
            user_password="pw",
        )
        user_role = await _named_role(session, "user")
        user_role.api_key_permission = None
        await session.commit()
        await seed_db(
            session,
            admin_username="root",
            admin_email="root@example.com",
            admin_password="pw",
            user_username="joe",
            user_email="joe@example.com",
            user_password="pw",
        )
        user_role = await _named_role(session, "user")
        assert isinstance(user_role.api_key_permission, ApiKeyAccess)

    async def test_partial_user_credentials_rejected(self, session: AsyncSession) -> None:
        with pytest.raises(ValueError, match="fully provided"):
            await seed_db(
                session,
                admin_username="root",
                admin_email="root@example.com",
                admin_password="pw",
                user_username="joe",
                user_email=None,
                user_password=None,
            )

    async def test_user_role_permission_is_self_scoped(self, session: AsyncSession) -> None:
        """The seeded user role's ApiKeyAccess scopes to the principal's own keys."""
        await seed_db(
            session,
            admin_username="root",
            admin_email="root@example.com",
            admin_password="pw",
            user_username="joe",
            user_email="joe@example.com",
            user_password="pw",
        )
        user_role = await _named_role(session, "user")
        policy = user_role.api_key_permission
        assert isinstance(policy, ApiKeyAccess)
        uid = uuid.uuid4()
        filt = policy.to_search_filter(uid, Action.READ)
        assert isinstance(filt, ApiKeyAccessFilter)
        assert filt.user_id == uid
        # Anonymous is denied (NoneSearchFilter, not None).
        assert policy.to_search_filter(None, Action.CREATE) is not None


async def _admin_role(session: AsyncSession, user_id: uuid.UUID) -> Role:
    """The admin role assigned to *user_id*."""
    stmt = (
        select(Role).join(UserRole, UserRole.role_id == Role.id).where(UserRole.user_id == user_id)
    )
    role = await session.scalar(stmt)
    assert role is not None, "admin role not assigned to user"
    return role


async def _named_role(session: AsyncSession, name: str) -> Role:
    role = await session.scalar(select(Role).where(Role.name == name))
    assert role is not None, f"role {name!r} not seeded"
    return role
